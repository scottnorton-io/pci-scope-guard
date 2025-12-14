"""
PCI Scope Guard - Cryptographic Evidence Signer
ECDSA signing for immutable compliance evidence
"""

import hashlib
import json
from typing import Optional, Dict
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import base64
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class EvidenceSigner:
    """
    Cryptographic signer for compliance evidence
    
    Uses ECDSA (Elliptic Curve Digital Signature Algorithm) for
    signing evidence artifacts. Signatures are stored with evidence
    to prove authenticity and detect tampering.
    """
    
    def __init__(self, private_key_path: str, public_key_path: Optional[str] = None):
        \"\"\"
        Initialize signer with key paths
        
        Args:
            private_key_path: Path to PEM-encoded ECDSA private key
            public_key_path: Optional path to public key (for verification)
        \"\"\"
        self.private_key_path = private_key_path
        self.public_key_path = public_key_path
        
        # Load keys
        self._private_key = self._load_private_key()
        self._public_key = self._load_public_key() if public_key_path else None
        
        logger.info(\"Initialized Evidence Signer\")
    
    def _load_private_key(self) -> ec.EllipticCurvePrivateKey:
        \"\"\"Load ECDSA private key from file\"\"\"
        try:
            with open(self.private_key_path, 'rb') as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
            
            if not isinstance(private_key, ec.EllipticCurvePrivateKey):
                raise ValueError(\"Key must be an ECDSA private key\")
            
            logger.info(\"Loaded ECDSA private key\")
            return private_key
            
        except Exception as e:
            logger.error(f\"Failed to load private key: {e}\")
            raise
    
    def _load_public_key(self) -> ec.EllipticCurvePublicKey:
        \"\"\"Load ECDSA public key from file\"\"\"
        try:
            with open(self.public_key_path, 'rb') as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
            
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise ValueError(\"Key must be an ECDSA public key\")
            
            logger.info(\"Loaded ECDSA public key\")
            return public_key
            
        except Exception as e:
            logger.error(f\"Failed to load public key: {e}\")
            raise
    
    def hash_evidence(self, evidence_data: Dict) -> str:
        \"\"\"
        Generate SHA-256 hash of evidence data
        
        Args:
            evidence_data: Evidence payload to hash
            
        Returns:
            Hex-encoded SHA-256 hash
        \"\"\"
        # Convert to canonical JSON (sorted keys, no whitespace)
        canonical_json = json.dumps(
            evidence_data,
            sort_keys=True,
            separators=(',', ':')
        )
        
        # Generate hash
        hash_obj = hashlib.sha256(canonical_json.encode('utf-8'))
        return hash_obj.hexdigest()
    
    def sign_evidence(self, evidence_data: Dict) -> Dict[str, str]:
        \"\"\"
        Sign evidence data with ECDSA private key
        
        Args:
            evidence_data: Evidence payload to sign
            
        Returns:
            Dict containing hash, signature, and metadata
        \"\"\"
        # Generate hash
        evidence_hash = self.hash_evidence(evidence_data)
        
        # Sign the hash
        signature = self._private_key.sign(
            evidence_hash.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
        )
        
        # Base64 encode signature for storage
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        
        logger.info(f\"Signed evidence with hash {evidence_hash[:16]}...\")
        
        return {
            'hash': evidence_hash,
            'signature': signature_b64,
            'algorithm': 'ECDSA-SHA256',
            'signed_at': datetime.utcnow().isoformat(),
            'key_id': self._get_key_identifier()
        }
    
    def verify_signature(
        self, 
        evidence_data: Dict, 
        signature_b64: str
    ) -> bool:
        \"\"\"
        Verify evidence signature
        
        Args:
            evidence_data: Evidence payload
            signature_b64: Base64-encoded signature
            
        Returns:
            True if signature is valid
        \"\"\"
        if not self._public_key:
            raise ValueError(\"Public key required for verification\")
        
        try:
            # Regenerate hash
            evidence_hash = self.hash_evidence(evidence_data)
            
            # Decode signature
            signature = base64.b64decode(signature_b64)
            
            # Verify
            self._public_key.verify(
                signature,
                evidence_hash.encode('utf-8'),
                ec.ECDSA(hashes.SHA256())
            )
            
            logger.info(f\"Signature verified for hash {evidence_hash[:16]}...\")
            return True
            
        except InvalidSignature:
            logger.warning(\"Invalid signature detected\")
            return False
        except Exception as e:
            logger.error(f\"Signature verification failed: {e}\")
            return False
    
    def _get_key_identifier(self) -> str:
        \"\"\"Generate identifier for signing key\"\"\"
        # Use public key fingerprint as identifier
        public_key = self._private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        fingerprint = hashlib.sha256(public_pem).hexdigest()
        return f\"ecdsa-sha256:{fingerprint[:16]}\"
    
    @staticmethod
    def generate_key_pair(output_dir: str = \".\") -> tuple:
        \"\"\"
        Generate new ECDSA key pair
        
        Args:
            output_dir: Directory to save keys
            
        Returns:
            Tuple of (private_key_path, public_key_path)
        \"\"\"
        # Generate private key
        private_key = ec.generate_private_key(
            ec.SECP256R1(),  # NIST P-256 curve
            default_backend()
        )
        
        # Save private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        private_key_path = f\"{output_dir}/evidence-signing-key.pem\"
        with open(private_key_path, 'wb') as f:
            f.write(private_pem)
        
        # Save public key
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        public_key_path = f\"{output_dir}/evidence-signing-key.pub\"
        with open(public_key_path, 'wb') as f:
            f.write(public_pem)
        
        logger.info(f\"Generated key pair: {private_key_path}, {public_key_path}\")
        
        return (private_key_path, public_key_path)
