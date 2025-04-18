import pytest
from datetime import datetime
from src.modules.storage.models import Target, Credential, Plugin, Utilisateur
from src.modules.storage.database import Database

class TestDatabase:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.db = Database(":memory:")
        
    def test_execute_query(self):
        result = self.db.execute_query("SELECT 1")
        assert result == [(1,)]

class TestModels:
    def test_target_model(self):
        target = Target(id=1, username='test_user', hash='test_hash')
        assert target.id == 1
        assert target.username == 'test_user'
        assert target.hash == 'test_hash'

    def test_credential_model(self):
        credential = Credential(username='test_user', hash='test_hash', id=1)
        assert credential.id == 1
        assert credential.username == 'test_user'
        assert credential.ntlm_hash == 'test_hash'

    def test_plugin_model(self):
        plugin = Plugin(
            id_plugin=1,
            nom_plugin="Test Plugin",
            description="Test Description",
            version="1.0",
            ntlm_key="test_key",
            date_creation=datetime.now()
        )
        assert plugin.id_plugin == 1
        assert plugin.nom_plugin == "Test Plugin"

    def test_utilisateur_model(self):
        user = Utilisateur(
            id_utilisateur=1,
            prenom_utilisateur="Test User",
            role_utilisateur="admin",
            email_utilisateur="test@example.com",
            derniere_connexion=datetime.now()
        )
        assert user.id_utilisateur == 1
        assert user.prenom_utilisateur == "Test User"