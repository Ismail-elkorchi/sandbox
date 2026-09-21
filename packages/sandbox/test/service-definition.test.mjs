import assert from 'node:assert/strict';
import test from 'node:test';
import { renderSandsurfServiceDefinition } from '../dist/index.js';

const directory = '/state/agent one';
const binary = '/opt/sandsurf/bin/sandsurf-host';

test('service definitions bind one explicit state store on every supported host', () => {
  const linux = renderSandsurfServiceDefinition({ directory, binary, platform: 'linux' });
  assert.equal(linux.format, 'systemd-user');
  assert.match(linux.contents, /NoNewPrivileges=true/u);
  assert.match(linux.contents, /serve --directory "\/state\/agent one"/u);

  const macos = renderSandsurfServiceDefinition({ directory, binary, platform: 'macos' });
  assert.equal(macos.format, 'launchd-agent');
  assert.match(macos.contents, /<string>serve<\/string>/u);
  assert.match(macos.contents, /<string>\/state\/agent one<\/string>/u);

  const windows = renderSandsurfServiceDefinition({
    directory: 'C:\\Sandsurf State',
    binary: 'C:\\Program Files\\Sandsurf\\sandsurf-host.exe',
    platform: 'windows'
  });
  assert.equal(windows.format, 'windows-scm-powershell');
  assert.match(windows.contents, /New-Service/u);
  assert.match(windows.contents, /service --directory/u);
  assert.match(windows.contents, /--service-name/u);
  assert.match(windows.contents, /-Credential/u);

  assert.equal(linux.name, renderSandsurfServiceDefinition({ directory, binary, platform: 'linux' }).name);
});
