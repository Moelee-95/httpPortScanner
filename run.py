"""Bounded TCP scanner for authorized security assessments. Python 3.10+."""
import argparse
import concurrent.futures as futures
import csv
import datetime
import http.client
import ipaddress
import json
import socket
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

COMMON = '21,22,23,25,53,80,110,135,139,143,443,445,465,587,993,995,1433,2049,2375,3000,3306,3389,5432,5900,6379,8000,8080,8443,9200,11211,27017'
WEB = {80,443,3000,5000,8000,8008,8080,8081,8443,8888,9000,9200}
EXPOSURES = {21:'FTP: review encryption and anonymous access.',23:'Telnet: replace plaintext remote access with SSH.',445:'SMB: restrict access to trusted networks.',2375:'Possible plaintext Docker API: verify authentication and network restrictions.',3389:'RDP: restrict access and require strong authentication.',6379:'Possible Redis: verify authentication and network restrictions.',9200:'Possible Elasticsearch: verify authentication and network restrictions.',11211:'Possible Memcached: restrict network access.',27017:'Possible MongoDB: verify authentication and network restrictions.'}


def parse_ports(value):
    ports = set()
    try:
        for item in value.split(','):
            bounds = item.strip().split('-')
            if len(bounds) == 1:
                start = end = int(bounds[0])
            elif len(bounds) == 2:
                start, end = map(int, bounds)
            else:
                raise ValueError
            if not 1 <= start <= end <= 65535:
                raise ValueError
            ports.update(range(start, end + 1))
    except ValueError:
        raise argparse.ArgumentTypeError('Use ports 1-65535, e.g. 22,80,443,8000-8100') from None
    return sorted(ports)


def parse_target(value):
    value = value.strip()
    try:
        ipaddress.ip_address(value)
        return value, None
    except ValueError:
        pass
    parsed = urlsplit(value if '://' in value else '//' + value)
    if parsed.scheme and parsed.scheme not in {'http','https'}:
        raise ValueError('Only HTTP(S) URLs are supported')
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Provide a hostname, IP, or URL without credentials')
    if parsed.path not in {'','/'} or parsed.query or parsed.fragment:
        raise ValueError('Provide a host without a path, query, or fragment')
    port = parsed.port
    if port == 0:
        raise ValueError('URL port must be 1-65535')
    return parsed.hostname, port


def connect(address, family, port, timeout):
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((address, port))
    except BaseException:
        sock.close()
        raise
    return sock


def web_probe(host, address, family, port, timeout, tls):
    sock = connect(address, family, port, timeout)
    result = {'scheme':'https' if tls else 'http'}
    try:
        if tls:
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
            result['tls'] = {'verified':True, 'version':sock.version(), 'cipher':sock.cipher()[0], 'expires':sock.getpeercert().get('notAfter')}
        authority = f'[{host}]' if ':' in host else host.encode('idna').decode('ascii')
        sock.sendall((f'HEAD / HTTP/1.1\r\nHost: {authority}:{port}\r\nUser-Agent: SecurityPortScanner/1.0\r\nConnection: close\r\n\r\n').encode('ascii'))
        response = http.client.HTTPResponse(sock)
        response.begin()
        result.update(status=response.status, headers={k.lower():v for k,v in response.getheaders()})
        response.close()
        return result
    finally:
        sock.close()


def scan_port(host, address, family, port, timeout, web=False, scheme='auto'):
    started = time.monotonic()
    result = {'port':port, 'state':'closed', 'service':'unknown', 'findings':[]}
    try:
        with connect(address, family, port, timeout):
            pass
    except (socket.timeout, TimeoutError):
        result['state'] = 'timeout'
    except ConnectionRefusedError:
        pass
    except OSError as exc:
        result.update(state='error', error=str(exc))
    else:
        result['state'] = 'open'
        try:
            result['service'] = socket.getservbyport(port, 'tcp')
        except OSError:
            pass
        if port in EXPOSURES:
            result['findings'].append(EXPOSURES[port])
        if web and (port in WEB or scheme != 'auto'):
            tls = scheme == 'https' or (scheme == 'auto' and port in {443,8443})
            try:
                result['web'] = web_probe(host,address,family,port,timeout,tls)
                headers = result['web']['headers']
                checks = ['content-security-policy','x-content-type-options']
                if tls:
                    checks.append('strict-transport-security')
                for header in checks:
                    if header not in headers:
                        result['findings'].append(f'Missing {header}; review for browser-facing applications.')
            except ssl.SSLCertVerificationError as exc:
                result['probe_error'] = f'TLS certificate verification failed: {exc.verify_message}'
                result['findings'].append(result['probe_error'])
            except (OSError, http.client.HTTPException, ValueError) as exc:
                result['probe_error'] = str(exc)
    result['elapsed_ms'] = round((time.monotonic()-started)*1000,2)
    return result


def run_scan(host, address, family, ports, args):
    results, pending = [], set()
    iterator = iter(ports)
    pool = futures.ThreadPoolExecutor(max_workers=args.workers)
    interrupted = False
    def submit():
        port = next(iterator, None)
        if port is not None:
            pending.add(pool.submit(scan_port,host,address,family,port,args.timeout,args.web,args.scheme))
    try:
        for _ in range(min(args.workers,len(ports))):
            submit()
        while pending:
            done, pending = futures.wait(pending,return_when=futures.FIRST_COMPLETED)
            for future in done:
                result = future.result()
                results.append(result)
                if result['state'] == 'open':
                    print(f"  {result['port']}/tcp open ({result['service']})",file=sys.stderr)
                submit()
    except KeyboardInterrupt:
        interrupted = True
        print('\nInterrupted; retaining completed results.',file=sys.stderr)
    finally:
        for future in pending:
            future.cancel()
        pool.shutdown(wait=True,cancel_futures=True)
    return sorted(results,key=lambda r:r['port']), interrupted


def write_report(report, filename, fmt):
    if fmt == 'json':
        Path(filename).write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    else:
        with open(filename,'w',newline='',encoding='utf-8') as stream:
            writer = csv.DictWriter(stream,fieldnames=['host','address','port','state','service','elapsed_ms','findings','web','probe_error','error'])
            writer.writeheader()
            for result in report['results']:
                row = dict(result,host=report['host'],address=report['address'])
                row['findings'] = ' | '.join(row['findings'])
                row['web'] = json.dumps(row.get('web',{}))
                writer.writerow(row)


def interactive_arguments():
    """Collect validated settings and reuse the regular command-line scan path."""
    def ask(label, default, validate):
        while True:
            value = input(f'{label} [{default}]: ').strip() or default
            try:
                validate(value)
                return value
            except (ValueError, argparse.ArgumentTypeError) as exc:
                print(f'Invalid input: {exc}')

    def choice(options):
        def validate(value):
            if value not in options:
                raise ValueError('choose ' + ', '.join(options))
        return validate

    def number(convert, low, high):
        def validate(value):
            if not low <= convert(value) <= high:
                raise ValueError(f'enter a number from {low} to {high}')
        return validate

    def ports(value):
        if value not in {'default', 'all'}:
            parse_ports(value)

    print('Security Port Scanner — interactive setup')
    print('Press Enter to accept defaults. Ctrl+C cancels.')
    target = ask('Target hostname, IP, or URL', '127.0.0.1', parse_target)
    selected = ask('Ports (default, all, or e.g. 22,80,443,8000-8100)', 'default', ports)
    arguments = [target]
    if selected == 'all':
        arguments.append('--all-ports')
    elif selected != 'default':
        arguments.extend(['--ports', selected])
    if ask('Check HTTP/TLS? (y/n)', 'n', choice(['y', 'n'])) == 'y':
        arguments.append('--web')
        arguments.extend(['--scheme', ask('Web protocol', 'auto', choice(['auto', 'http', 'https']))])
    arguments.extend(['--workers', ask('Concurrent probes', '64', number(int, 1, 256))])
    arguments.extend(['--timeout', ask('Timeout in seconds', '1.5', number(float, 0.1, 30))])
    arguments.extend(['--family', ask('Address family (auto/4/6)', 'auto', choice(['auto', '4', '6']))])
    if ask('Show closed/timeout/error ports? (y/n)', 'n', choice(['y', 'n'])) == 'y':
        arguments.append('--show-all')
    output = input('Report filename (blank to skip; existing files are overwritten): ').strip()
    if output:
        fmt = ask('Report format', 'csv' if output.lower().endswith('.csv') else 'json', choice(['json', 'csv']))
        arguments.extend(['--output', output, '--format', fmt])
    return arguments


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        try:
            argv = interactive_arguments()
        except (KeyboardInterrupt, EOFError):
            print('\nSetup cancelled; no scan started.', file=sys.stderr)
            return 130
    parser = argparse.ArgumentParser(description=__doc__,epilog='Scan only systems you own or have permission to assess.')
    parser.add_argument('target',help='hostname, IPv4/IPv6 address, or HTTP(S) URL')
    parser.add_argument('-p','--ports',type=parse_ports,help='ports/ranges; default: common ports, or explicit URL port')
    parser.add_argument('--all-ports',action='store_true',help='scan TCP ports 1-65535')
    parser.add_argument('-w','--workers',type=int,default=64,help='concurrent probes, 1-256 (default: 64)')
    parser.add_argument('-t','--timeout',type=float,default=1.5,help='socket operation timeout, 0.1-30 seconds (default: 1.5)')
    parser.add_argument('--web',action='store_true',help='HEAD / on recognized web ports')
    parser.add_argument('--scheme',choices=['auto','http','https'],default='auto',help='force HTTP(S) on all open ports; requires --web')
    parser.add_argument('--family',choices=['auto','4','6'],default='auto')
    parser.add_argument('-o','--output',help='report file (overwrites existing file)')
    parser.add_argument('--format',choices=['json','csv'],default='json')
    parser.add_argument('--show-all',action='store_true',help='also print closed, timeout, and error ports')
    args = parser.parse_args(argv)
    if not 1 <= args.workers <= 256 or not 0.1 <= args.timeout <= 30:
        parser.error('workers must be 1-256 and timeout must be 0.1-30 seconds')
    if args.all_ports and args.ports:
        parser.error('use either --ports or --all-ports')
    if args.scheme != 'auto' and not args.web:
        parser.error('--scheme requires --web')
    try:
        host,url_port = parse_target(args.target)
        family = {'auto':socket.AF_UNSPEC,'4':socket.AF_INET,'6':socket.AF_INET6}[args.family]
        resolved = socket.getaddrinfo(host,None,family,socket.SOCK_STREAM)[0]
        family,address = resolved[0],resolved[4][0]
    except (ValueError,OSError) as exc:
        parser.error(str(exc))
    ports = list(range(1,65536)) if args.all_ports else args.ports or ([url_port] if url_port else parse_ports(COMMON))
    print(f'Scanning {host} ({address}), {len(ports)} TCP ports',file=sys.stderr)
    started = time.monotonic()
    results,interrupted = run_scan(host,address,family,ports,args)
    report = {'host':host,'address':address,'timestamp_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'duration_seconds':round(time.monotonic()-started,3),'interrupted':interrupted,'requested_ports':len(ports),'completed_ports':len(results),'results':results}
    counts = {state:sum(r['state']==state for r in results) for state in ['open','closed','timeout','error']}
    print('\n'+', '.join(f'{count} {state}' for state,count in counts.items()))
    for result in results:
        if args.show_all or result['state']=='open':
            print(f"{result['port']}/tcp {result['state']} ({result['service']})")
            if 'web' in result:
                print(f"  {result['web']['scheme'].upper()} {result['web']['status']}")
            for finding in result['findings']:
                print(f'  Review: {finding}')
            for key in ['probe_error','error']:
                if key in result:
                    print(f'  {key}: {result[key]}')
    if args.output:
        try:
            write_report(report,args.output,args.format)
        except OSError as exc:
            print(f'Cannot write report: {exc}',file=sys.stderr)
            return 1
        print(f'Report saved to {args.output}')
    return 130 if interrupted else (1 if counts['error'] else 0)


if __name__ == '__main__':
    sys.exit(main())
