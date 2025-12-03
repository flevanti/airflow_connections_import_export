"""
Airflow Connections Migration Utility
================================================

This script enables secure export and import of Airflow connection records between Airflow environments that use different Fernet keys.
Connections details are shared via an encrypted CSV file, ensuring sensitive information remains protected during transit.

Core Capabilities
-----------------
1. **Export Airflow Connections**
   - Decrypts connection data stored in the Airflow Postgres metadata DB using a *source/system Fernet key*.
   - Add a prefix to connection IDs to avoid collisions during import (optional).
   - Re-encrypts the entire connection record into a JSON payload using a *temporary/shared-file Fernet key*.
   - Produces a CSV file (`airflow_connections.csv`) containing:
       conn_id, encrypted_connection_json

2. **Import Airflow Connections**
   - Reads the exported CSV.
   - Decrypts stored JSON using the *file/shared Fernet key*.
   - Re-encrypts sensitive fields using the *target-system Fernet key*.
   - Validates that no `conn_id` already exists in the target environment (primary-key protection).
   - Requests explicit user confirmation before inserting data.

3. **Fernet Key Handling**
   - Keys can be provided via CLI (`--decrypt-key` and `--encrypt-key`) or interactively.
   - During export, if the new key is left blank, a random key will be generated.

Usage
-----
Run the tool interactively:

    python airflow_connections_export_import.py

Provide the desired operation when prompted:
    [E] Export connections
    [I] Import connections
    [Q] Quit

Or use CLI arguments for automated workflows:

    python airflow_connections_export_import.py --operation E --decrypt-key <SOURCE_KEY> --encrypt-key <FILE_KEY> --conn-id-prefix <PREFIX>

    python airflow_connections_export_import.py --operation I --decrypt-key <FILE_KEY> --encrypt-key <TARGET_KEY>

Typical Workflow
----------------
1. **On Source Environment**
      python airflow_connections_export_import.py --operation E --decrypt-key <SOURCE_FERNET_KEY>
   A random temporary key may be generated unless you provide `--encrypt-key`.

2. **Share Output**
   - `airflow_connections.csv`
   - The shared-file Fernet key is printed on screen if it was generated randomly.

3. **On Target Environment**
      python [script name] --operation I --decrypt-key <FILE_KEY> --encrypt-key <TARGET_FERNET_KEY>

4. The script:
   - Decrypts the file
   - Validates IDs
   - Requests confirmation
   - Inserts into Airflow's `public.connection` table

Notes
-----
- This script assumes a local Airflow default Postgres DB, but you may
  modify the `DB_CONFIG` dictionary as needed.
- Connection IDs are treated as unique identifiers, matching Airflow’s schema.
- No connections are written unless you explicitly confirm insertion.
- Connection ID prefix has a maximum length of 10 characters to avoid overly long IDs.
- Fernet keys are not changed/updated in Airflow; this tool only handles connection records migration and uses keys already in place
"""

import argparse
from getpass import getpass
from cryptography.fernet import Fernet
import psycopg2
import psycopg2.extras
import json
import csv

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------

# Default local Airflow Postgres connection (dev environment)
# TODO move this info to a config file or environment variables as needed
DB_CONFIG = {
    "host": "127.0.0.1",
    "port": 5432,
    "user": "postgres",
    "password": "postgres",
    "dbname": "postgres"
}

EXPORTED_FILENAME = "airflow_connections.csv"


# ----------------------------------------------------------------------
# Cryptography helpers
# ----------------------------------------------------------------------

def decrypt_value(f: Fernet, value: str) -> str | None:
    """
    Decrypts a string value using the provided Fernet instance.
    Returns None if the value is None.
    Raises an exception on any decryption error.
    """
    if value is None:
        return None
    try:
        return f.decrypt(value.encode("utf-8")).decode("utf-8")
    except Exception as e:
        raise Exception(f"Decryption failed for value: {value} with error: {e}")


def encrypt_value(f: Fernet, value: str) -> str | None:
    """
    Encrypts a string value using the provided Fernet instance.
    Returns None if the value is None.
    Raises an exception on any encryption error.
    """
    if value is None:
        return None
    try:
        return f.encrypt(value.encode("utf-8")).decode("utf-8")
    except Exception as e:
        raise Exception(f"Warning: Encryption failed for value: {value} with error: {e}")


# ----------------------------------------------------------------------
# CLI input and menu utilities
# ----------------------------------------------------------------------

def read_key(cli_key, prompt_label) -> str:
    """
    Returns the provided key if given via CLI.
    Otherwise, prompts the user to type the key without echo.
    """
    if cli_key is not None:
        return cli_key
    return getpass(f"Enter [{prompt_label}] Fernet key: ")


def import_or_export(cli_operation) -> str:
    """
    Determines whether to run Export or Import based on CLI arguments.
    If CLI argument is missing, shows a menu and prompts the user.
    Returns 'E', 'I', or 'Q'.
    """
    if cli_operation:
        print(f'Using provided operation: [{cli_operation}]')
        return cli_operation.upper()

    valid = {"E", "I", "Q"}
    print("[E] - export airflow connections to file")
    print("[I] - import airflow connections from file")
    print("[Q] - quit")

    while True:
        choice = input("Select an option (E/I/Q): ").strip().upper()
        if choice in valid:
            return choice


def parse_cli_args() -> argparse.Namespace:
    """
    Parses command line arguments:
    --decrypt-key: Fernet key used for decrypting source or shared file
    --encrypt-key: Fernet key used for encrypting output or target system
    --operation: E or I to skip menu prompt
    """
    parser = argparse.ArgumentParser(description="Decrypt and re-encrypt Airflow connection records from Postgres.")
    parser.add_argument("--decrypt-key", help="decrypt Fernet key for decryption of source system or shared file.")
    parser.add_argument("--encrypt-key",
                        help="New Fernet key for encryption of the shared file or imported info in target system.")
    parser.add_argument("--operation", help="Export [E] or Import [I] connections file", choices=['E', 'I'])
    parser.add_argument("--conn-id-prefix",
                        help="Add a prefix to the connection ids to prevent collisions during import")

    return parser.parse_args()


def get_fernet_keys(operation: str, decrypt_key: str, encrypt_key: str) -> tuple[str, str, bool]:
    """
    Collects decrypt_key and encrypt_key from CLI or user prompt.
    In EXPORT mode, if encrypt_key is blank, generates a new Fernet key.
    Returns (decrypt_key, encrypt_key, encrypt_key_is_generated).
    """
    encrypt_key_is_generated = False
    if operation == "E":
        decrypt_key_label = "source system encryption key"
        encrypt_key_label = "Encryption key for shared file (leave blank to generate random key)"
    else:
        decrypt_key_label = "Decryption key for shared file"
        encrypt_key_label = "target system encryption key"

    decrypt_key = read_key(decrypt_key, decrypt_key_label)
    encrypt_key = read_key(encrypt_key, encrypt_key_label)

    if operation == "E" and encrypt_key == "":
        encrypt_key = Fernet.generate_key().decode("utf-8")
        encrypt_key_is_generated = True

    return decrypt_key, encrypt_key, encrypt_key_is_generated


# ----------------------------------------------------------------------
# Export logic
# ----------------------------------------------------------------------

def export_connections(fernet_source, fernet_file, conn_id_prefix="") -> None:
    """
    Reads connections directly from Airflow Postgres,
    decrypts password and extra (if flagged),
    encrypts the full connection JSON using the provided file key,
    and writes a CSV file containing (conn_id, encrypted_json).
    """
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute('SELECT conn_id, conn_type, description, host, schema, login, password, port, is_encrypted, is_extra_encrypted, extra FROM public.connection')
    rows = cur.fetchall()

    csv_like_output = []

    for row in rows:
        # Apply prefix to conn_id if provided to avoid collisions during import
        row["conn_id"] = f"{conn_id_prefix}{row.get('conn_id')}"

        print(f"Exporting source connection ID to encrypted file: {row.get('conn_id')}")

        # Encrypted values are replaced with decrypted versions
        if row.get("is_encrypted"):
            row["password"] = decrypt_value(fernet_source, row.get("password"))

        if row.get("is_extra_encrypted"):
            row["extra"] = decrypt_value(fernet_source, row.get("extra"))

        row_encrypted_json = encrypt_value(fernet_file, json.dumps(row))
        csv_like_output.append((row.get("conn_id"), row_encrypted_json))

    cur.close()
    conn.close()

    with open(EXPORTED_FILENAME, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["conn_id", "encrypted_connection"])
        writer.writerows(csv_like_output)


# ----------------------------------------------------------------------
# Import logic
# ----------------------------------------------------------------------

def decrypt_file(fernet_file, fernet_target, file_path) -> list:
    """
    Reads the CSV file created by export, decrypts each JSON row
    using fernet_file, then re-encrypts password and extra
    using fernet_target if their flags are True.
    Returns a list of connection dictionaries.
    """
    connections = []

    with open(file_path, mode="r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            conn_id = row["conn_id"]
            encrypted_json = row["encrypted_connection"]
            print(f"Extracting from shared file encrypted connection ID: {conn_id}")

            decrypted_json_str = decrypt_value(fernet_file, encrypted_json)

            conn_data = json.loads(decrypted_json_str)

            if conn_data.get("is_encrypted") and conn_data.get("password") is not None:
                conn_data["password"] = encrypt_value(fernet_target, conn_data.get("password"))

            if conn_data.get("is_extra_encrypted") and conn_data.get("extra") is not None:
                conn_data["extra"] = encrypt_value(fernet_target, conn_data.get("extra"))

            connections.append(conn_data)

    print("\nDone! Connections loaded in memory ready to be imported.")
    return connections


def check_if_connections_exist_in_target_airflow(connections) -> list:
    """
    Given a list of connection dictionaries, checks the Airflow DB
    for existing conn_ids.
    Returns a list of conn_ids that already exist.
    """
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    existing_ids = []
    conn_ids = [c["conn_id"] for c in connections]

    if conn_ids:
        cur.execute(
            "SELECT conn_id FROM public.connection WHERE conn_id = ANY(%s)",
            (conn_ids,)
        )
        existing_ids = [row[0] for row in cur.fetchall()]

    cur.close()
    conn.close()
    return existing_ids


def insert_connections_into_target_airflow_db(connections) -> None:
    """
    Inserts the provided list of connection dictionaries into the Airflow DB.
    Fails fast on the first error.
    """
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    for c in connections:
        try:
            cur.execute("""
                        INSERT INTO public.connection
                        (conn_id, conn_type, description, host, schema, login, password, port,
                         is_encrypted, is_extra_encrypted, extra)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """, (
                            c.get("conn_id"),
                            c.get("conn_type"),
                            c.get("description"),
                            c.get("host"),
                            c.get("schema"),
                            c.get("login"),
                            c.get("password"),
                            c.get("port"),
                            c.get("is_encrypted"),
                            c.get("is_extra_encrypted"),
                            c.get("extra")
                        ))
        except Exception as e:
            raise Exception(f"Error while saving connection id {c.get('conn_id')}: {e}")

    conn.commit()
    cur.close()
    conn.close()
    print(f"{len(connections)} connections inserted successfully.")


def confirmation_before_import() -> bool:
    """
    Prompts the user for confirmation before proceeding with the import.
    Returns True if the user confirms, False otherwise.
    """
    confirm = input("Do you want to proceed? (Y/N): ").strip().upper()
    return confirm == "Y"


def import_connections_with_confirmation(connections) -> None:
    """
    Validates the connection set by checking for pre-existing conn_ids.
    If none exist, prompts user for confirmation
    before inserting all connections into the DB.
    """
    print("\nChecking if any connection IDs already exist in target Airflow DB...")
    existing = check_if_connections_exist_in_target_airflow(connections)
    if existing:
        raise Exception(f"Existing conn_id(s) found in target Airflow DB: {existing}")

    print(f"{len(connections)} connections ready to insert.")
    if not confirmation_before_import():
        print("Import canceled by user.")
        return

    insert_connections_into_target_airflow_db(connections)


def import_connections(fernet_file, fernet_target, file_path="") -> None:
    """
    Orchestrates the import process:
    decrypts the file,
    re-encrypts necessary fields,
    checks DB state,
    asks for confirmation,
    inserts into Airflow DB.
    """
    if file_path == "":
        file_path = EXPORTED_FILENAME

    connections = decrypt_file(fernet_file, fernet_target, file_path)
    import_connections_with_confirmation(connections)


def get_connection_prefix(cli_prefix: str) -> str:
    """
    Returns the provided connection ID prefix if given via CLI.
    Otherwise, prompts the user to type the prefix.
    """
    max_len = 10

    conn_id_prefix = cli_prefix.strip() if cli_prefix is not None else None

    if cli_prefix is None:
        conn_id_prefix = input(
            f"Enter connection ID prefix to prevent collisions (leave blank for none, max len {max_len} characters): ").strip()

    if len(conn_id_prefix) > 10:
        raise Exception(
            f"Connection ID prefix too long, max length allowed 10 characters. Provided prefix length: {len(conn_id_prefix)}")

    return conn_id_prefix


# ----------------------------------------------------------------------
# Main entrypoint
# ----------------------------------------------------------------------

def main() -> None:
    """
    Main program flow: parse CLI args, gather keys, execute export or import,
    print the generated key (if created).
    """
    args = parse_cli_args()

    operation = import_or_export(args.operation)

    if operation == "Q":
        print("Quitting.")
        return

    decrypt_key, encrypt_key, encrypt_key_is_generated = get_fernet_keys(operation, args.decrypt_key, args.encrypt_key)

    fernet_decrypt = Fernet(decrypt_key)
    fernet_encrypt = Fernet(encrypt_key)

    if operation == "E":
        conn_id_prefix = get_connection_prefix(args.conn_id_prefix)
        print("\n→ EXPORT operation selected: Decrypting from source system and encrypting to shared file.\n")
        if len(conn_id_prefix) > 0:
            print(f"→ Connection ID prefix to be applied during export: [{conn_id_prefix}]\n")
        export_connections(fernet_decrypt, fernet_encrypt, conn_id_prefix)
    else:
        print("\n→ IMPORT operation selected: Decrypting from shared file and encrypting to target system.\n")
        import_connections(fernet_decrypt, fernet_encrypt)

    if encrypt_key_is_generated:
        print(f"\n\n → Generated new Fernet key to encrypt shared file: [{encrypt_key}]\n\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n🔴 Ouch, something went wrong!\n\n{e}")
