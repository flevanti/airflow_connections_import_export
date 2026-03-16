import argparse
from getpass import getpass
from cryptography.fernet import Fernet
import psycopg
from psycopg.rows import dict_row
import json
import csv

DB_CONFIG = {
    "host": "127.0.0.1",
    "port": 5432,
    "user": "postgres",
    "password": "postgres",
    "dbname": "postgres"
}

EXPORTED_FILENAME = "airflow_connections.csv"


def decrypt_value(f: Fernet, value: str):
    if value is None:
        return None
    try:
        return f.decrypt(value.encode("utf-8")).decode("utf-8")
    except Exception as e:
        raise Exception(f"Decryption failed for value: {value} with error: {e}")


def encrypt_value(f: Fernet, value: str):
    if value is None:
        return None
    try:
        return f.encrypt(value.encode("utf-8")).decode("utf-8")
    except Exception as e:
        raise Exception(f"Encryption failed for value: {value} with error: {e}")


def read_key(cli_key, prompt_label):
    if cli_key is not None:
        return cli_key
    return getpass(f"Enter [{prompt_label}] Fernet key: ")


def import_or_export(cli_operation):
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


def parse_cli_args():
    parser = argparse.ArgumentParser(
        description="Decrypt and re-encrypt Airflow connection records from Postgres."
    )

    parser.add_argument("--decrypt-key")
    parser.add_argument("--encrypt-key")
    parser.add_argument("--operation", choices=["E", "I"])
    parser.add_argument("--conn-id-prefix")

    return parser.parse_args()


def get_fernet_keys(operation, decrypt_key, encrypt_key):
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


def export_connections(fernet_source, fernet_file, conn_id_prefix=""):

    with psycopg.connect(**DB_CONFIG) as conn:
        with conn.cursor(row_factory=dict_row) as cur:

            cur.execute("""
                SELECT conn_id, conn_type, description, host, schema, login,
                       password, port, is_encrypted, is_extra_encrypted, extra
                FROM public.connection
            """)

            rows = cur.fetchall()

    csv_like_output = []

    for row in rows:

        row["conn_id"] = f"{conn_id_prefix}{row.get('conn_id')}"

        print(f"Exporting source connection ID to encrypted file: {row.get('conn_id')}")

        if row.get("is_encrypted"):
            row["password"] = decrypt_value(fernet_source, row.get("password"))

        if row.get("is_extra_encrypted"):
            row["extra"] = decrypt_value(fernet_source, row.get("extra"))

        row_encrypted_json = encrypt_value(fernet_file, json.dumps(row))
        csv_like_output.append((row.get("conn_id"), row_encrypted_json))

    with open(EXPORTED_FILENAME, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["conn_id", "encrypted_connection"])
        writer.writerows(csv_like_output)


def decrypt_file(fernet_file, fernet_target, file_path):

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
                conn_data["password"] = encrypt_value(
                    fernet_target, conn_data.get("password")
                )

            if conn_data.get("is_extra_encrypted") and conn_data.get("extra") is not None:
                conn_data["extra"] = encrypt_value(
                    fernet_target, conn_data.get("extra")
                )

            connections.append(conn_data)

    print("\nDone! Connections loaded in memory ready to be imported.")
    return connections


def check_if_connections_exist_in_target_airflow(connections):

    conn_ids = [c["conn_id"] for c in connections]

    if not conn_ids:
        return []

    with psycopg.connect(**DB_CONFIG) as conn:
        with conn.cursor() as cur:

            cur.execute(
                "SELECT conn_id FROM public.connection WHERE conn_id = ANY(%s)",
                (conn_ids,)
            )

            existing_ids = [row[0] for row in cur.fetchall()]

    return existing_ids


def insert_connections_into_target_airflow_db(connections):

    with psycopg.connect(**DB_CONFIG) as conn:
        with conn.cursor() as cur:

            for c in connections:

                try:
                    cur.execute("""
                        INSERT INTO public.connection
                        (conn_id, conn_type, description, host, schema, login,
                         password, port, is_encrypted, is_extra_encrypted, extra)
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
                    raise Exception(
                        f"Error while saving connection id {c.get('conn_id')}: {e}"
                    )

        conn.commit()

    print(f"{len(connections)} connections inserted successfully.")


def confirmation_before_import():

    confirm = input("Do you want to proceed? (Y/N): ").strip().upper()
    return confirm == "Y"


def import_connections_with_confirmation(connections):

    print("\nChecking if any connection IDs already exist in target Airflow DB...")

    existing = check_if_connections_exist_in_target_airflow(connections)

    if existing:
        raise Exception(
            f"Existing conn_id(s) found in target Airflow DB: {existing}"
        )

    print(f"{len(connections)} connections ready to insert.")

    if not confirmation_before_import():
        print("Import canceled by user.")
        return

    insert_connections_into_target_airflow_db(connections)


def import_connections(fernet_file, fernet_target, file_path=""):

    if file_path == "":
        file_path = EXPORTED_FILENAME

    connections = decrypt_file(fernet_file, fernet_target, file_path)

    import_connections_with_confirmation(connections)


def get_connection_prefix(cli_prefix):

    max_len = 10

    conn_id_prefix = cli_prefix.strip() if cli_prefix is not None else None

    if cli_prefix is None:
        conn_id_prefix = input(
            f"Enter connection ID prefix to prevent collisions "
            f"(leave blank for none, max len {max_len} characters): "
        ).strip()

    if len(conn_id_prefix) > max_len:
        raise Exception(
            f"Connection ID prefix too long. Max allowed {max_len}, "
            f"provided {len(conn_id_prefix)}"
        )

    return conn_id_prefix


def main():

    args = parse_cli_args()

    operation = import_or_export(args.operation)

    if operation == "Q":
        print("Quitting.")
        return

    decrypt_key, encrypt_key, encrypt_key_is_generated = get_fernet_keys(
        operation, args.decrypt_key, args.encrypt_key
    )

    fernet_decrypt = Fernet(decrypt_key)
    fernet_encrypt = Fernet(encrypt_key)

    if operation == "E":

        conn_id_prefix = get_connection_prefix(args.conn_id_prefix)

        print("\n→ EXPORT operation selected\n")

        export_connections(fernet_decrypt, fernet_encrypt, conn_id_prefix)

    else:

        print("\n→ IMPORT operation selected\n")

        import_connections(fernet_decrypt, fernet_encrypt)

    if encrypt_key_is_generated:
        print(
            f"\n\nGenerated new Fernet key for shared file encryption:\n{encrypt_key}\n"
        )


if __name__ == "__main__":

    try:
        main()
    except Exception as e:
        print(f"\n🔴 Ouch, something went wrong!\n\n{e}")