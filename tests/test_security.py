
import pytest
import sys
import os

from sqlalchemy import create_engine
from werkzeug.security import generate_password_hash

# Find app.py in the main TrustVault folder
sys.path.insert(
    0,
    os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

from app import app, db, User, Document, Permission


@pytest.fixture
def client(tmp_path):
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    with app.app_context():

        db.session.remove()

        engine_map = db.engines
        original_engine = engine_map[None]

        test_engine = create_engine(
            f"sqlite:///{tmp_path / 'test.db'}"
        )

        engine_map[None] = test_engine

        db.create_all()

        alice = User(
            username="alice",
            email="alice@test.com",
            password=generate_password_hash("password123"),
            role="Owner"
        )

        bob = User(
            username="bob",
            email="bob@test.com",
            password=generate_password_hash("password123"),
            role="Owner"
        )

        db.session.add_all([alice, bob])
        db.session.commit()

        document = Document(
            title="Private Document",
            description="Test file",
            filename="test.txt",
            original_name="test.txt",
            file_hash="testhash",
            owner_id=alice.id
        )

        db.session.add(document)
        db.session.commit()

        document_id = document.id
        bob_id = bob.id

        with app.test_client() as test_client:
            yield test_client, document_id, bob_id

        db.session.remove()
        db.drop_all()

        engine_map[None] = original_engine
        test_engine.dispose()


def login(test_client, email):
    return test_client.post(
        "/login",
        data={
            "email": email,
            "password": "password123"
        },
        follow_redirects=True
    )


def test_private_document_blocked(client):
    test_client, document_id, bob_id = client

    login(test_client, "bob@test.com")

    response = test_client.get(
        f"/documents/{document_id}/download"
    )

    assert response.status_code == 403


def test_shared_document_access(client):
    test_client, document_id, bob_id = client

    with app.app_context():
        permission = Permission(
            document_id=document_id,
            user_id=bob_id,
            can_edit=False
        )

        db.session.add(permission)
        db.session.commit()

    login(test_client, "bob@test.com")

    response = test_client.get(
        f"/documents/{document_id}"
    )

    assert response.status_code == 200


def test_revoked_document_access(client):
    test_client, document_id, bob_id = client

    with app.app_context():
        permission = Permission(
            document_id=document_id,
            user_id=bob_id,
            can_edit=False
        )

        db.session.add(permission)
        db.session.commit()

    # Login as Alice
    login(test_client, "alice@test.com")

    # Revoke Bob's permission
    response = test_client.post(
        f"/documents/{document_id}/revoke/{bob_id}",
        follow_redirects=True
    )

    assert response.status_code == 200

    # Logout Alice
    test_client.get("/logout")

    # Login as Bob
    login(test_client, "bob@test.com")

    # Bob should not access the document
    response = test_client.get(
        f"/documents/{document_id}"
    )

    assert response.status_code == 403
