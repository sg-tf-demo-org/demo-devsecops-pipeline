# Compliant twin — parameterized SQL; no pickle.loads on untrusted input.


def find_user(conn, username):
    query = "SELECT * FROM users WHERE name = ?"
    return conn.execute(query, (username,))


def load_session(blob):
    raise NotImplementedError(
        "Do not deserialize untrusted blobs with pickle; use a signed JSON session store"
    )
