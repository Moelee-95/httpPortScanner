import contextlib
import csv
import http.server
import io
import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import run


class ScannerTests(unittest.TestCase):
    def test_interactive_defaults_start_scan(self):
        with patch('builtins.input', side_effect=[''] * 9), patch('run.run_scan', return_value=([], False)) as scan, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(run.main([]), 0)
        self.assertEqual(scan.call_args.args[0], '127.0.0.1')
        self.assertEqual(scan.call_args.args[3], run.parse_ports(run.COMMON))

    def test_interactive_validation_and_custom_options(self):
        answers = ['localhost', '0', '80,443', 'maybe', 'y', 'https', '0', '8', 'nan', '2', '4', 'y', 'report.csv', 'csv']
        with patch('builtins.input', side_effect=answers), contextlib.redirect_stdout(io.StringIO()):
            arguments = run.interactive_arguments()
        self.assertEqual(arguments, ['localhost', '--ports', '80,443', '--web', '--scheme', 'https', '--workers', '8', '--timeout', '2', '--family', '4', '--show-all', '--output', 'report.csv', '--format', 'csv'])

    def test_interactive_cancel(self):
        for exception in [EOFError, KeyboardInterrupt]:
            with patch('builtins.input', side_effect=exception), patch('run.run_scan') as scan, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(run.main([]), 130)
                scan.assert_not_called()

    def test_ports(self):
        self.assertEqual(run.parse_ports('443,80-82,80'), [80,81,82,443])
        for value in ['0','65536','4-2','1-2-3','','abc']:
            with self.assertRaises(Exception):
                run.parse_ports(value)

    def test_targets(self):
        self.assertEqual(run.parse_target('https://localhost:8443'), ('localhost',8443))
        self.assertEqual(run.parse_target('::1'), ('::1',None))
        self.assertEqual(run.parse_target('[::1]:8080'), ('::1',8080))
        for value in ['http://user:password@localhost','https://localhost/path','ftp://localhost','localhost:bad']:
            with self.assertRaises(ValueError):
                run.parse_target(value)

    def test_closed_port(self):
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1',0))
            port = reserved.getsockname()[1]
            result = run.scan_port('localhost','127.0.0.1',socket.AF_INET,port,3)
        self.assertEqual(result['state'],'closed')

    def test_timeout_and_errors(self):
        for exception,state in [(socket.timeout(),'timeout'),(OSError('unreachable'),'error')]:
            with patch('run.connect',side_effect=exception):
                self.assertEqual(run.scan_port('localhost','127.0.0.1',socket.AF_INET,1,.2)['state'],state)

    def test_tls_verification_failure(self):
        class Connection:
            def __enter__(self): return self
            def __exit__(self,*args): pass
        with patch('run.connect',return_value=Connection()), patch('run.web_probe',side_effect=run.ssl.SSLCertVerificationError(1,'untrusted')):
            # Real verification exceptions have verify_message populated by OpenSSL.
            exc = run.ssl.SSLCertVerificationError(1,'untrusted')
            exc.verify_message = 'untrusted'
            with patch('run.web_probe',side_effect=exc):
                result = run.scan_port('localhost','127.0.0.1',socket.AF_INET,443,.2,True)
        self.assertEqual(result['state'],'open')
        self.assertIn('untrusted',result['probe_error'])

    def test_local_http_cli_and_reports(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_HEAD(self):
                self.send_response(401)
                self.send_header('X-Content-Type-Options','nosniff')
                self.end_headers()
            def log_message(self,*args): pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread = threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                destination = Path(directory)/'report.json'
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    code = run.main(['127.0.0.1','-p',str(server.server_port),'--web','--scheme','http','-o',str(destination)])
                self.assertEqual(code,0)
                report = json.loads(destination.read_text())
                self.assertEqual(report['completed_ports'],1)
                result = report['results'][0]
                self.assertEqual(result['state'],'open')
                self.assertEqual(result['web']['status'],401)
                self.assertEqual(len(result['findings']),1)
                csv_path = Path(directory)/'report.csv'
                run.write_report(report,csv_path,'csv')
                with csv_path.open(newline='') as stream:
                    rows = list(csv.DictReader(stream))
                self.assertEqual(rows[0]['port'],str(server.server_port))
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_invalid_cli(self):
        for arguments in [['localhost','--workers','0'],['localhost','--timeout','nan'],['localhost','--scheme','https'],['localhost','-p','80','--all-ports']]:
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                run.main(arguments)
            self.assertEqual(caught.exception.code,2)


if __name__ == '__main__':
    unittest.main()
