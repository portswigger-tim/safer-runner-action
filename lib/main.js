"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const core = __importStar(require("@actions/core"));
const exec = __importStar(require("@actions/exec"));
async function run() {
    try {
        const mode = core.getInput('mode') || 'analyze';
        const allowedDomains = core.getInput('allowed-domains') || '';
        core.info(`🛡️ Starting Safer Runner Action in ${mode} mode`);
        // Step 1: Install dependencies
        core.info('Installing dependencies...');
        await exec.exec('sudo', ['apt-get', 'update', '-qq']);
        await exec.exec('sudo', ['apt-get', 'install', '-y', 'dnsmasq', 'ipset']);
        // Step 2: Configure iptables rules
        core.info('Configuring iptables rules...');
        await setupFirewallRules();
        // Step 3: Configure DNS filtering
        core.info('Configuring DNS filtering...');
        await setupDNSConfig();
        // Step 4: Configure DNSMasq
        core.info('Configuring DNSMasq...');
        await setupDNSMasq(mode, allowedDomains);
        // Step 5: Start services
        core.info('Starting services...');
        await startServices();
        // Step 6: Finalize security rules
        core.info('Finalizing security rules...');
        await finalizeSecurityRules(mode);
        core.info(`✅ Safer Runner Action configured successfully in ${mode} mode`);
    }
    catch (error) {
        core.setFailed(`Action failed with error: ${error}`);
    }
}
async function setupFirewallRules() {
    // Allow established and related connections
    await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-m', 'state', '--state', 'ESTABLISHED,RELATED', '-j', 'ACCEPT']);
    // Allow Azure metadata service (required for GitHub Actions)
    await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-o', 'eth0', '-d', '168.63.129.16', '-j', 'ACCEPT']);
    await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-o', 'eth0', '-d', '169.254.169.254', '-j', 'ACCEPT']);
    // Allow localhost traffic
    await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-o', 'lo', '-s', '127.0.0.1', '-d', '127.0.0.1', '-j', 'ACCEPT']);
    // Log processing for debugging
    await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-j', 'LOG', '--log-prefix=Processing: ']);
    // Create ipset for GitHub Actions required domains
    await exec.exec('sudo', ['ipset', 'create', 'github', 'hash:ip']);
    await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-m', 'set', '--match-set', 'github', 'dst', '-j', 'LOG', '--log-prefix=GitHub-Allow: ']);
    await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-m', 'set', '--match-set', 'github', 'dst', '-j', 'ACCEPT']);
    // Create ipset for user allowed domains
    await exec.exec('sudo', ['ipset', 'create', 'user', 'hash:ip']);
    await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-m', 'set', '--match-set', 'user', 'dst', '-j', 'LOG', '--log-prefix=User-Allow: ']);
    await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-m', 'set', '--match-set', 'user', 'dst', '-j', 'ACCEPT']);
}
async function setupDNSConfig() {
    // Configure systemd-resolved to use our DNS server
    await exec.exec('sudo', ['mkdir', '-p', '/etc/systemd/resolved.conf.d']);
    const resolvedConfig = `[Resolve]
DNS=127.0.0.1
DNSSEC=yes
DNSStubListener=no`;
    await exec.exec('sudo', ['tee', '/etc/systemd/resolved.conf.d/no-stub.conf'], {
        input: Buffer.from(resolvedConfig)
    });
    // Update resolv.conf to use localhost
    await exec.exec('sudo', ['unlink', '/etc/resolv.conf']);
    await exec.exec('sudo', ['tee', '/etc/resolv.conf'], {
        input: Buffer.from('nameserver 127.0.0.1\n')
    });
}
async function setupDNSMasq(mode, allowedDomains) {
    const dnsServer = '9.9.9.9';
    let dnsmasqConfig = `# Enable query logging for summary generation
log-queries=extra

`;
    // Configure DNS policy based on mode
    if (mode === 'enforce') {
        dnsmasqConfig += 'server=\n'; // NXDOMAIN all unlisted DNS (default deny)
    }
    else {
        dnsmasqConfig += `server=${dnsServer}\n`; // Analyze mode: allow all DNS queries
    }
    // Add GitHub required domains
    const githubDomains = [
        'github.com', 'actions.githubusercontent.com', 'api.github.com',
        'codeload.github.com', 'pkg.actions.githubusercontent.com', 'ghcr.io',
        'results-receiver.actions.githubusercontent.com',
        // Add all the productionresultssa domains...
        ...Array.from({ length: 20 }, (_, i) => `productionresultssa${i}.blob.core.windows.net`),
        'objects.githubusercontent.com', 'objects-origin.githubusercontent.com',
        'github-releases.githubusercontent.com', 'github-registry-files.githubusercontent.com',
        'pkg.github.com', 'pkg-containers.githubusercontent.com',
        'github-cloud.githubusercontent.com', 'github-cloud.s3.amazonaws.com',
        'dependabot-actions.githubapp.com', 'release-assets.githubusercontent.com',
        'api.snapcraft.io'
    ];
    for (const domain of githubDomains) {
        dnsmasqConfig += `server=/${domain}/${dnsServer}\n`;
        dnsmasqConfig += `ipset=/${domain}/github\n`;
    }
    // Add custom allowed domains if provided
    if (allowedDomains) {
        for (const domain of allowedDomains.split(' ').filter(d => d.trim())) {
            dnsmasqConfig += `server=/${domain}/${dnsServer}\n`;
            dnsmasqConfig += `ipset=/${domain}/user\n`;
        }
    }
    await exec.exec('sudo', ['tee', '/etc/dnsmasq.conf'], {
        input: Buffer.from(dnsmasqConfig)
    });
}
async function startServices() {
    const dnsServer = '9.9.9.9';
    // Restart systemd-resolved and start dnsmasq
    await exec.exec('sudo', ['systemctl', 'restart', 'systemd-resolved']);
    await exec.exec('sudo', ['systemctl', 'enable', 'dnsmasq']);
    await exec.exec('sudo', ['systemctl', 'start', 'dnsmasq']);
    // Allow DNS traffic to our upstream server
    await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-o', 'eth0', '-d', dnsServer, '-p', 'udp', '--dport', '53', '-m', 'owner', '--uid-owner', 'dnsmasq', '-j', 'ACCEPT']);
}
async function finalizeSecurityRules(mode) {
    if (mode === 'enforce') {
        // Log dropped packets for debugging
        await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-o', 'eth0', '-j', 'LOG', '--log-prefix=Drop-Enforce: ']);
        // DEFAULT DENY: Drop external traffic not explicitly allowed (scoped to eth0)
        await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-o', 'eth0', '-j', 'DROP']);
    }
    else {
        // Log other traffic for analysis but allow it
        await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-j', 'LOG', '--log-prefix=Allow-Analyze: ']);
        await exec.exec('sudo', ['iptables', '-A', 'OUTPUT', '-j', 'ACCEPT']);
    }
}
run();
