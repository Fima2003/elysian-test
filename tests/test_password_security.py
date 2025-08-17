"""
Test coverage for password hashing and validation.
Tests password security functions, hashing, verification, and strength validation.
"""

import pytest
import bcrypt
import sys
import os
from unittest.mock import patch, MagicMock

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.security import hash_password, verify_password
from models.user import UserCreate, UserLogin


class TestPasswordHashing:
    """Test cases for password hashing functions."""
    
    def test_hash_password_returns_string(self):
        """Test that hash_password returns string."""
        password = "TestPassword123!"
        hashed = hash_password(password)
        
        assert isinstance(hashed, str)
        assert len(hashed) > 0
    
    def test_hash_password_different_for_same_input(self):
        """Test that hash_password generates different hashes for the same input (salt)."""
        password = "TestPassword123!"
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        
        assert hash1 != hash2  # Due to different salts
    
    def test_hash_password_with_empty_string(self):
        """Test hash_password with empty string."""
        password = ""
        hashed = hash_password(password)
        
        assert isinstance(hashed, str)
        assert len(hashed) > 0
    
    def test_hash_password_with_unicode(self):
        """Test hash_password with unicode characters."""
        password = "Tëst🔐Pässwörd123!"
        hashed = hash_password(password)
        
        assert isinstance(hashed, str)
        assert len(hashed) > 0
    
    def test_hash_password_with_very_long_password(self):
        """Test hash_password with very long password."""
        password = "a" * 1000  # 1000 character password
        hashed = hash_password(password)
        
        assert isinstance(hashed, str)
        assert len(hashed) > 0
    
    def test_hash_password_bcrypt_integration(self):
        """Test actual bcrypt integration (not mocked)."""
        password = "TestPassword123!"
        hashed = hash_password(password)
        
        # Should be a valid bcrypt hash (returned as string)
        assert hashed.startswith('$2b$')
        assert len(hashed) == 60  # Standard bcrypt hash length
        
        # Should be verifiable with our verify_password function
        assert verify_password(password, hashed)


class TestPasswordVerification:
    """Test cases for password verification functions."""
    
    def test_verify_password_correct_password(self):
        """Test verify_password with correct password."""
        password = "TestPassword123!"
        hashed = hash_password(password)
        
        result = verify_password(password, hashed)
        
        assert result is True
    
    def test_verify_password_incorrect_password(self):
        """Test verify_password with incorrect password."""
        password = "TestPassword123!"
        wrong_password = "WrongPassword123!"
        hashed = hash_password(password)
        
        result = verify_password(wrong_password, hashed)
        
        assert result is False
    
    def test_verify_password_empty_password(self):
        """Test verify_password with empty password."""
        password = "TestPassword123!"
        hashed = hash_password(password)
        
        result = verify_password("", hashed)
        
        assert result is False
    
    def test_verify_password_none_password(self):
        """Test verify_password with None password."""
        password = "TestPassword123!"
        hashed = hash_password(password)
        
        with pytest.raises((TypeError, AttributeError)):
            verify_password(None, hashed)
    
    def test_verify_password_invalid_hash(self):
        """Test verify_password with invalid hash."""
        password = "TestPassword123!"
        invalid_hash = b"invalid_hash"
        
        with pytest.raises(ValueError):
            verify_password(password, invalid_hash)
    
    def test_verify_password_none_hash(self):
        """Test verify_password with None hash."""
        password = "TestPassword123!"
        
        with pytest.raises((TypeError, AttributeError)):
            verify_password(password, None)
    
    def test_verify_password_case_sensitive(self):
        """Test that password verification is case sensitive."""
        password = "TestPassword123!"
        case_different = "testpassword123!"
        hashed = hash_password(password)
        
        result = verify_password(case_different, hashed)
        
        assert result is False
    
    def test_verify_password_unicode_characters(self):
        """Test verify_password with unicode characters."""
        password = "Tëst🔐Pässwörd123!"
        hashed = hash_password(password)
        
        result = verify_password(password, hashed)
        
        assert result is True
    
    @patch('bcrypt.checkpw')
    def test_verify_password_uses_bcrypt(self, mock_checkpw):
        """Test that verify_password uses bcrypt.checkpw."""
        mock_checkpw.return_value = True
        
        password = "TestPassword123!"
        hashed_password = b'$2b$12$test_hash'
        
        result = verify_password(password, hashed_password)
        
        mock_checkpw.assert_called_once_with(password.encode('utf-8'), hashed_password)
        assert result is True


class TestPasswordValidation:
    """Test cases for password validation in models."""
    
    def test_user_create_valid_password(self):
        """Test UserCreate with valid password."""
        user_data = {
            "email": "test@example.com",
            "password": "TestPassword123!"
        }
        
        user = UserCreate(**user_data)
        
        assert user.password == "TestPassword123!"
    
    def test_user_create_minimum_length_password(self):
        """Test UserCreate with minimum length password."""
        user_data = {
            "email": "test@example.com",
            "password": "123456"  # Exactly 6 characters
        }
        
        user = UserCreate(**user_data)
        
        assert user.password == "123456"
    
    def test_user_create_short_password(self):
        """Test UserCreate with password that's too short."""
        with pytest.raises(ValueError, match="Password must be at least 6 characters"):
            UserCreate(email="test@example.com", password="12345")
    
    def test_user_create_empty_password(self):
        """Test UserCreate with empty password."""
        with pytest.raises(ValueError, match="Password must be at least 6 characters"):
            UserCreate(email="test@example.com", password="")
    
    def test_user_create_whitespace_only_password(self):
        """Test UserCreate with whitespace-only password."""
        with pytest.raises(ValueError, match="Password must be at least 6 characters"):
            UserCreate(email="test@example.com", password="   ")
    
    def test_user_create_password_with_spaces(self):
        """Test UserCreate with password containing spaces (should be trimmed)."""
        user_data = {
            "email": "test@example.com",
            "password": "  TestPassword123!  "
        }
        
        user = UserCreate(**user_data)
        
        assert user.password == "TestPassword123!"  # Trimmed
    
    def test_user_create_very_long_password(self):
        """Test UserCreate with very long password."""
        long_password = "a" * 128  # Maximum length
        user_data = {
            "email": "test@example.com",
            "password": long_password
        }
        
        user = UserCreate(**user_data)
        
        assert user.password == long_password
    
    def test_user_create_too_long_password(self):
        """Test UserCreate with password exceeding maximum length."""
        with pytest.raises(ValueError, match="Password must be at most 128 characters long"):
            UserCreate(email="test@example.com", password="a" * 129)
    
    def test_user_login_password_validation(self):
        """Test UserLogin password validation."""
        login_data = {
            "email": "test@example.com",
            "password": "TestPassword123!"
        }
        
        user_login = UserLogin(**login_data)
        
        assert user_login.password == "TestPassword123!"
    
    def test_user_login_empty_password(self):
        """Test UserLogin with empty password."""
        with pytest.raises(ValueError, match="Password cannot be empty"):
            UserLogin(email="test@example.com", password="")


class TestPasswordSecurity:
    """Test cases for password security features."""
    
    def test_password_hash_complexity(self):
        """Test that password hashes have sufficient complexity."""
        from config import get_config
        config = get_config()
        
        passwords = [
            "simple123",
            "Complex123!",
            "VeryComplexPassword123!@#",
            "🔐SecurePassword🔐"
        ]
        
        hashes = [hash_password(p) for p in passwords]
        
        # All hashes should be different
        assert len(set(hashes)) == len(hashes)
        
        # All should start with bcrypt prefix with configured rounds
        expected_prefix = f'$2b${config.BCRYPT_ROUNDS:02d}$'
        for h in hashes:
            assert h.startswith(expected_prefix)
    
    def test_timing_attack_resistance(self):
        """Test that password verification has consistent timing (basic test)."""
        import time
        
        password = "TestPassword123!"
        hashed = hash_password(password)
        
        # Time correct password verification
        start = time.time()
        verify_password(password, hashed)
        correct_time = time.time() - start
        
        # Time incorrect password verification
        start = time.time()
        verify_password("WrongPassword", hashed)
        incorrect_time = time.time() - start
        
        # Both should take similar time (within reasonable variance)
        # This is a basic test - in practice, bcrypt handles timing attacks
        ratio = max(correct_time, incorrect_time) / min(correct_time, incorrect_time)
        assert ratio < 10  # Should not differ by more than 10x
    
    def test_hash_salt_uniqueness(self):
        """Test that each hash uses a unique salt."""
        password = "TestPassword123!"
        hashes = [hash_password(password) for _ in range(10)]
        
        # Extract salt from each hash (first 29 characters of bcrypt hash)
        salts = [h[:29] for h in hashes]
        
        # All salts should be unique
        assert len(set(salts)) == len(salts)
    
    def test_bcrypt_rounds_configuration(self):
        """Test that bcrypt uses appropriate number of rounds."""
        from config import get_config
        config = get_config()
        
        password = "TestPassword123!"
        hashed = hash_password(password)
        
        # Extract rounds from hash (characters 4-6 of bcrypt hash)
        rounds_str = hashed.split('$')[2]
        rounds = int(rounds_str)
        
        # Should match configured rounds
        assert rounds == config.BCRYPT_ROUNDS
    
    def test_password_strength_scenarios(self):
        """Test password verification with various strength scenarios."""
        test_cases = [
            ("weak", "weak"),
            ("123456", "123456"),
            ("password", "password"),
            ("Password123", "Password123"),
            ("P@ssw0rd!", "P@ssw0rd!"),
            ("VeryLongAndComplexPassword123!@#", "VeryLongAndComplexPassword123!@#")
        ]
        
        for password, verify_password_input in test_cases:
            hashed = hash_password(password)
            assert verify_password(verify_password_input, hashed) is True
            assert verify_password("wrong_password", hashed) is False


class TestPasswordErrorHandling:
    """Test cases for password error handling."""
    
    def test_hash_password_handles_encoding_errors(self):
        """Test hash_password handles various encoding scenarios."""
        # Test with different character encodings
        passwords = [
            "ASCII password",
            "UTF-8 pásswörd",
            "Emoji password 😀🔐",
            "Mixed ñ characters 中文"
        ]
        
        for password in passwords:
            hashed = hash_password(password)
            assert isinstance(hashed, str)  # hash_password returns string
            assert verify_password(password, hashed) is True
    
    def test_verify_password_handles_corrupted_hash(self):
        """Test verify_password with corrupted hash."""
        password = "TestPassword123!"
        
        # Use a severely corrupted hash that will trigger ValueError
        corrupted_hash = "invalid_hash_format"
        
        with pytest.raises(ValueError):
            verify_password(password, corrupted_hash)
    
    def test_verify_password_with_wrong_hash_format(self):
        """Test verify_password with wrong hash format."""
        password = "TestPassword123!"
        wrong_format_hash = b"plaintext_not_hash"
        
        with pytest.raises(ValueError):
            verify_password(password, wrong_format_hash)
    
    @patch('bcrypt.hashpw')
    def test_hash_password_handles_bcrypt_exception(self, mock_hashpw):
        """Test hash_password handles bcrypt exceptions."""
        mock_hashpw.side_effect = Exception("Bcrypt error")
        
        with pytest.raises(Exception, match="Bcrypt error"):
            hash_password("TestPassword123!")
    
    @patch('bcrypt.checkpw')
    def test_verify_password_handles_bcrypt_exception(self, mock_checkpw):
        """Test verify_password handles bcrypt exceptions."""
        mock_checkpw.side_effect = Exception("Bcrypt verify error")
        
        # Should return False when bcrypt raises unexpected exception
        result = verify_password("TestPassword123!", "$2b$12$test_hash")
        assert result is False
