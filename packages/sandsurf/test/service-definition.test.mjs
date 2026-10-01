import assert from 'node:assert/strict';
import test from 'node:test';
import { renderSandsurfServiceDefinition } from '../dist/index.js';

const directory = '/state/agent one';
const binary = '/opt/sandsurf/bin/sandsurf-host';

test('host API and guardian supervision have independent native service owners', () => {
  const linux = renderSandsurfServiceDefinition({ directory, binary, platform: 'linux' });
  assert.equal(linux.format, 'systemd-user');
  assert.equal(linux.files.length, 2);
  const [supervisor, host] = linux.files;
  assert.match(supervisor.contents, /supervise --directory "\/state\/agent one"/u);
  assert.match(host.contents, /serve --directory "\/state\/agent one"/u);
  assert.ok(host.contents.includes(`Wants=${supervisor.name}`));
  assert.match(host.name, /^sandsurf-api-id-[a-f0-9]{64}\.service$/u);
  assert.match(supervisor.name, /^sandsurf-supervisor-id-[a-f0-9]{64}\.service$/u);
  for (const property of ["CPUQuota=100%", "MemoryMax=134217728", "MemorySwapMax=0", "TasksMax=64", "Delegate=no"]) {
    assert.ok(supervisor.contents.includes(`${property}\n`));
  }
  for (const property of ["CPUQuota=100%", "MemoryMax=536870912", "MemorySwapMax=0", "TasksMax=256", "Delegate=no"]) {
    assert.ok(host.contents.includes(`${property}\n`));
  }
  for (const file of linux.files) {
    assert.match(file.contents, /NoNewPrivileges=true/u);
    assert.doesNotMatch(file.contents, /KillMode=process|PartOf=|BindsTo=|PrivateTmp=/u);
  }

  const macos = renderSandsurfServiceDefinition({ directory, binary, platform: 'macos' });
  assert.equal(macos.files.length, 2);
  assert.match(macos.files[0].contents, /<string>supervise<\/string>/u);
  assert.match(macos.files[1].contents, /<string>serve<\/string>/u);
  assert.notEqual(macos.files[0].name, macos.files[1].name);

  const windows = renderSandsurfServiceDefinition({ directory: 'C:\\Sandsurf State', binary: 'C:\\Program Files\\Sandsurf\\sandsurf-host.exe', platform: 'windows' });
  assert.equal(windows.format, 'windows-scm-powershell');
  assert.equal(windows.files.length, 1);
  assert.equal((windows.files[0].contents.match(/New-Service/gu) ?? []).length, 2);
  assert.match(windows.files[0].contents, /--role supervisor/u);
  assert.match(windows.files[0].contents, /--role host/u);
  assert.match(windows.files[0].contents, /-DependsOn 'sandsurf-supervisor-/u);
  assert.match(windows.files[0].contents, /-Credential/u);
  assert.deepEqual(linux, renderSandsurfServiceDefinition({ directory, binary, platform: 'linux' }));
});

test('service paths are literal arguments, not unit syntax or environment expressions', () => {
  const result = renderSandsurfServiceDefinition({ directory: '/state/$name%h', binary, platform: 'linux' });
  assert.match(result.files[0].contents, /\/state\/\$\$name%%h/u);
  for (const platform of ['linux', 'macos', 'windows']) {
    assert.throws(() => renderSandsurfServiceDefinition({ directory: platform === 'windows' ? 'C:\\state\nExecStart=evil' : '/state\nExecStart=evil', binary: platform === 'windows' ? 'C:\\host.exe' : binary, platform }), /control/u);
  }
});
