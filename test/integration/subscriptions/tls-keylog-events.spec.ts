import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import * as https from 'https';
import * as tls from 'tls';

import { getLocal, TlsKeylogEvent } from "../../..";
import {
    expect,
    nodeOnly,
    getDeferred,
    delay,
    openRawTlsSocket
} from "../../test-utils";

nodeOnly(() => {
    describe("TLS keylog events", () => {
        let tempDir: string;
        let incomingKeylogFile: string;
        let upstreamKeylogFile: string;

        beforeEach(async () => {
            // Create temporary directory for keylog files
            tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mockttp-keylog-test-'));
            incomingKeylogFile = path.join(tempDir, 'incoming.keylog');
            upstreamKeylogFile = path.join(tempDir, 'upstream.keylog');
        });

        afterEach(async () => {
            // Clean up temporary files
            try {
                await fs.rm(tempDir, { recursive: true, force: true });
            } catch (e) {
                // Ignore cleanup errors
            }
        });

        describe("for incoming TLS connections", () => {
            let server = getLocal({
                https: {
                    keyPath: './test/fixtures/test-ca.key',
                    certPath: './test/fixtures/test-ca.pem',
                    sslKeylog: {
                        incomingKeylogFile: () => incomingKeylogFile
                    }
                }
            });

            beforeEach(() => server.start());
            afterEach(() => server.stop());

            it("should emit keylog events for incoming TLS connections", async () => {
                let seenKeylogPromise = getDeferred<TlsKeylogEvent>();
                await server.on('tls-keylog', (event) => {
                    if (event.connectionType === 'incoming') {
                        seenKeylogPromise.resolve(event);
                    }
                });

                await server.forGet('/').thenReply(200, "Test response");

                // Make a TLS request to trigger keylog event
                const tlsSocket = await openRawTlsSocket(server, {
                    rejectUnauthorized: false
                });

                tlsSocket.write('GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');
                tlsSocket.end();

                const keylogEvent = await seenKeylogPromise;

                expect(keylogEvent.connectionType).to.equal('incoming');
                expect(keylogEvent.keylogLine).to.be.a('string');
                expect(keylogEvent.keylogLine).to.match(/^(CLIENT_RANDOM|SERVER_HANDSHAKE_TRAFFIC_SECRET|CLIENT_HANDSHAKE_TRAFFIC_SECRET|SERVER_TRAFFIC_SECRET_0|CLIENT_TRAFFIC_SECRET_0|EXPORTER_SECRET) [0-9a-fA-F]+ [0-9a-fA-F]+$/);
                expect(keylogEvent.remoteAddress).to.be.a('string');
                expect(keylogEvent.remotePort).to.be.a('number');
                expect(keylogEvent.localAddress).to.be.a('string');
                expect(keylogEvent.localPort).to.equal(server.port);
            });

            it("should write keylog data to the configured file", async () => {
                await server.forGet('/').thenReply(200, "Test response");

                // Make a TLS request
                const tlsSocket = await openRawTlsSocket(server, {
                    rejectUnauthorized: false
                });

                tlsSocket.write('GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');
                tlsSocket.end();

                // Wait a bit for the keylog to be written
                await delay(100);

                // Check that the keylog file was created and contains data
                const keylogContent = await fs.readFile(incomingKeylogFile, 'utf8');
                expect(keylogContent).to.not.be.empty;
                expect(keylogContent).to.match(/^(CLIENT_RANDOM|SERVER_HANDSHAKE_TRAFFIC_SECRET|CLIENT_HANDSHAKE_TRAFFIC_SECRET|SERVER_TRAFFIC_SECRET_0|CLIENT_TRAFFIC_SECRET_0|EXPORTER_SECRET) [0-9a-fA-F]+ [0-9a-fA-F]+/m);
            });
        });

        describe("for upstream TLS connections", () => {
            let proxyServer = getLocal({
                https: {
                    keyPath: './test/fixtures/test-ca.key',
                    certPath: './test/fixtures/test-ca.pem',
                    sslKeylog: {
                        upstreamKeylogFile: () => upstreamKeylogFile
                    }
                }
            });

            let targetServer = getLocal({
                https: {
                    keyPath: './test/fixtures/test-ca.key',
                    certPath: './test/fixtures/test-ca.pem'
                }
            });

            beforeEach(async () => {
                await targetServer.start();
                await proxyServer.start();
            });

            afterEach(async () => {
                await proxyServer.stop();
                await targetServer.stop();
            });

            it("should emit keylog events for upstream TLS connections", async () => {
                let seenKeylogPromise = getDeferred<TlsKeylogEvent>();
                await proxyServer.on('tls-keylog', (event) => {
                    if (event.connectionType === 'upstream') {
                        seenKeylogPromise.resolve(event);
                    }
                });

                await targetServer.forGet('/target').thenReply(200, "Target response");
                await proxyServer.forGet('/target').thenPassThrough({
                    forwarding: { targetHost: 'localhost', targetPort: targetServer.port }
                });

                // Make a request through the proxy to trigger upstream connection
                const response = await https.get({
                    hostname: 'localhost',
                    port: proxyServer.port,
                    path: '/target',
                    rejectUnauthorized: false
                });

                const keylogEvent = await seenKeylogPromise;

                expect(keylogEvent.connectionType).to.equal('upstream');
                expect(keylogEvent.keylogLine).to.be.a('string');
                expect(keylogEvent.keylogLine).to.match(/^(CLIENT_RANDOM|SERVER_HANDSHAKE_TRAFFIC_SECRET|CLIENT_HANDSHAKE_TRAFFIC_SECRET|SERVER_TRAFFIC_SECRET_0|CLIENT_TRAFFIC_SECRET_0|EXPORTER_SECRET) [0-9a-fA-F]+ [0-9a-fA-F]+$/);
                expect(keylogEvent.remoteAddress).to.be.a('string');
                expect(keylogEvent.remotePort).to.be.a('number');
                expect(keylogEvent.localAddress).to.be.a('string');
                expect(keylogEvent.localPort).to.be.a('number');
            });

            it("should write upstream keylog data to the configured file", async () => {
                await targetServer.forGet('/target').thenReply(200, "Target response");
                await proxyServer.forGet('/target').thenPassThrough({
                    forwarding: { targetHost: 'localhost', targetPort: targetServer.port }
                });

                // Make a request through the proxy
                await https.get({
                    hostname: 'localhost',
                    port: proxyServer.port,
                    path: '/target',
                    rejectUnauthorized: false
                });

                // Wait a bit for the keylog to be written
                await delay(100);

                // Check that the keylog file was created and contains data
                const keylogContent = await fs.readFile(upstreamKeylogFile, 'utf8');
                expect(keylogContent).to.not.be.empty;
                expect(keylogContent).to.match(/^(CLIENT_RANDOM|SERVER_HANDSHAKE_TRAFFIC_SECRET|CLIENT_HANDSHAKE_TRAFFIC_SECRET|SERVER_TRAFFIC_SECRET_0|CLIENT_TRAFFIC_SECRET_0|EXPORTER_SECRET) [0-9a-fA-F]+ [0-9a-fA-F]+/m);
            });
        });

        describe("with both incoming and upstream keylog files configured", () => {
            let proxyServer = getLocal({
                https: {
                    keyPath: './test/fixtures/test-ca.key',
                    certPath: './test/fixtures/test-ca.pem',
                    sslKeylog: {
                        incomingKeylogFile: () => incomingKeylogFile,
                        upstreamKeylogFile: () => upstreamKeylogFile
                    }
                }
            });

            let targetServer = getLocal({
                https: {
                    keyPath: './test/fixtures/test-ca.key',
                    certPath: './test/fixtures/test-ca.pem'
                }
            });

            beforeEach(async () => {
                await targetServer.start();
                await proxyServer.start();
            });

            afterEach(async () => {
                await proxyServer.stop();
                await targetServer.stop();
            });

            it("should write keylog data to separate files for incoming and upstream connections", async () => {
                await targetServer.forGet('/target').thenReply(200, "Target response");
                await proxyServer.forGet('/target').thenPassThrough({
                    forwarding: { targetHost: 'localhost', targetPort: targetServer.port }
                });

                // Make a request through the proxy
                await https.get({
                    hostname: 'localhost',
                    port: proxyServer.port,
                    path: '/target',
                    rejectUnauthorized: false
                });

                // Wait a bit for the keylogs to be written
                await delay(200);

                // Check that both keylog files were created and contain data
                const incomingKeylogContent = await fs.readFile(incomingKeylogFile, 'utf8');
                const upstreamKeylogContent = await fs.readFile(upstreamKeylogFile, 'utf8');

                expect(incomingKeylogContent).to.not.be.empty;
                expect(upstreamKeylogContent).to.not.be.empty;

                expect(incomingKeylogContent).to.match(/^(CLIENT_RANDOM|SERVER_HANDSHAKE_TRAFFIC_SECRET|CLIENT_HANDSHAKE_TRAFFIC_SECRET|SERVER_TRAFFIC_SECRET_0|CLIENT_TRAFFIC_SECRET_0|EXPORTER_SECRET) [0-9a-fA-F]+ [0-9a-fA-F]+/m);
                expect(upstreamKeylogContent).to.match(/^(CLIENT_RANDOM|SERVER_HANDSHAKE_TRAFFIC_SECRET|CLIENT_HANDSHAKE_TRAFFIC_SECRET|SERVER_TRAFFIC_SECRET_0|CLIENT_TRAFFIC_SECRET_0|EXPORTER_SECRET) [0-9a-fA-F]+ [0-9a-fA-F]+/m);

                // The files should contain different keylog data
                expect(incomingKeylogContent).to.not.equal(upstreamKeylogContent);
            });
        });

        describe("without keylog configuration", () => {
            let server = getLocal({
                https: {
                    keyPath: './test/fixtures/test-ca.key',
                    certPath: './test/fixtures/test-ca.pem'
                }
            });

            beforeEach(() => server.start());
            afterEach(() => server.stop());

            it("should not emit keylog events when keylog is not configured", async () => {
                let keylogEventReceived = false;
                await server.on('tls-keylog', () => {
                    keylogEventReceived = true;
                });

                await server.forGet('/').thenReply(200, "Test response");

                // Make a TLS request
                const tlsSocket = await openRawTlsSocket(server, {
                    rejectUnauthorized: false
                });

                tlsSocket.write('GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');
                tlsSocket.end();

                // Wait a bit to ensure no keylog events are emitted
                await delay(100);

                expect(keylogEventReceived).to.be.false;
            });
        });
    });
});