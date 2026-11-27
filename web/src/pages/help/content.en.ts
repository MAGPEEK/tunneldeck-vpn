import type { HelpContent } from './content';

export const HELP_CONTENT_EN: HelpContent = {
  'getting-started': [
    {
      type: 'paragraph',
      text: 'Open `http://<host address>:8194` in a browser in your local LAN. The web UI is reachable from the LAN only, never through the VPN tunnel. Change address or port with the environment variable `TUNNELDECK_LISTEN` (for example `192.168.1.10:9000`); the System page shows the listen address in use.',
    },
    {
      type: 'list',
      items: [
        'On the first visit you create the admin account. The password needs at least 12 characters. There is exactly one admin account.',
        'Sign in with username and password. After every failed attempt, the address you sign in from has to wait before the next one: 10 seconds, then 20, 40 and so on, at most 15 minutes. The sign-in page counts the wait down. A successful sign-in resets it.',
        'Over remote access, 10 failed attempts within 10 minutes from any addresses block remote sign-in for everyone for 1 minute (longer if it happens again, at most 15 minutes). Sign-in on the LAN address keeps working.',
        '"Stay signed in" keeps this browser signed in for up to 90 days, also across container restarts; the session ends after 30 days without use. It is offered on the LAN address only, not over remote access.',
        '"Sign out everywhere" on the System page ends every session, remembered ones included.',
      ],
    },
    {
      type: 'paragraph',
      text: 'Then check that every entry on the System page passes, add a VPN profile under Profiles and connect on the Dashboard.',
    },
    { type: 'link', target: 'linux', text: 'Setup guide for Linux Docker hosts' },
    { type: 'link', target: 'synology', text: 'Setup guide for Synology DSM' },
  ],
  profiles: [
    {
      type: 'paragraph',
      text: 'A profile holds everything one VPN connection needs. You can store several profiles; one is active at a time.',
    },
    {
      type: 'terms',
      items: [
        {
          term: 'Load a profile file',
          text: 'Use "Load profile file (.ovpn, .conf)" for an OpenVPN or a WireGuard file, drop the file onto the Profiles page, or paste the configuration. The form opens filled in; nothing is stored until you save.',
        },
        {
          term: 'Missing fields',
          text: 'If the file lacks something the connection needs, for example username and password for `auth-user-pass` or a certificate it refers to as a separate file, the form highlights those fields. Fill them in before saving.',
        },
        {
          term: 'Import warnings',
          text: 'Lines that were changed or not imported are listed with the reason. Unknown directives are not imported.',
        },
        {
          term: 'Advisories',
          text: 'Outdated or weak settings are flagged in the form and on the Dashboard: an unencrypted data channel (`cipher none`), weak ciphers or digests, compression, `fragment`. They do not block the connection.',
        },
        {
          term: 'Extra options',
          text: "One OpenVPN 2.7 client directive per line, passed to OpenVPN. Some are dropped with a warning because TunnelDeck-VPN sets them itself or because they would change this device's routing: `nobind`, `remote-cert-tls` and `cipher` (use the profile fields), `redirect-gateway` (this device keeps its own default route), and deprecated ones such as `fast-io`. Lines that run scripts or write files (`up`, `script-security`, `log`, …) are rejected.",
        },
        {
          term: 'Secrets',
          text: 'Passwords and keys are stored encrypted and shown only as "Stored". Use "Replace" to change them.',
        },
        {
          term: 'Daily reconnect',
          text: 'Section "Schedule": "Reconnect once a day" at a time you choose, in the container\'s time zone (`TZ`). It runs only while this profile is connected.',
        },
        {
          term: 'Public address',
          text: 'Section "Access": the address your provider assigns to this connection, for example a fixed public IP. It always takes precedence over the public IP that TunnelDeck-VPN detects after every connect (System → Public IP detection). It is used for the remote-access URL and for port forwards. Leave it empty if the VPN address itself is reachable from the internet.',
        },
      ],
    },
    { type: 'subheading', text: 'WireGuard' },
    {
      type: 'list',
      items: [
        'Create a WireGuard profile with the form (protocol "WireGuard") or load the `.conf` file your server or provider gives you; pasting its text works too.',
        '"Generate key pair" creates a new private key for this device and shows the matching public key. Enter this public key on the server as the public key of this peer; the private key never leaves TunnelDeck-VPN and is stored encrypted.',
        '`DNS` from the file is not applied, the host keeps its own DNS settings; scripts (`PreUp`, `PostUp`, `PreDown`, `PostDown`) are not imported. Only the first peer and IPv4 entries are used.',
        '`AllowedIPs` other than `0.0.0.0/0` count as networks behind the VPN and are routed through the tunnel. Which LAN devices may use the tunnel is decided by the firewall rules and the kill switch, as for OpenVPN.',
        'While connecting without an answer from the server, the Dashboard says so after 30 seconds and keeps trying: check the keys and the endpoint.',
      ],
    },
    { type: 'subheading', text: 'IPsec/IKEv2' },
    {
      type: 'paragraph',
      text: 'Choose the protocol "IPsec/IKEv2" for company and router gateways such as LANCOM, FRITZ!Box, OPNsense, pfSense or strongSwan. IPsec profiles are created with the form; there is no file import.',
    },
    {
      type: 'terms',
      items: [
        {
          term: 'Gateway type',
          text: 'A template pre-fills the IKE version and the proposals the gateway family accepts, and shows where to find the values on the gateway. Fields you changed yourself keep your values; "Use template values" overwrites them.',
        },
        {
          term: 'Pre-shared key',
          text: 'A shared secret both sides know. Use a long random key of at least 20 characters.',
        },
        {
          term: 'Certificate',
          text: 'Load a PKCS#12 file (.p12, .pfx) with its password, or paste or load the client certificate and an unencrypted key in PEM format. The CA certificate of the gateway and the gateway identity are required; the identity must match the gateway certificate.',
        },
        {
          term: 'Username and password (EAP-MSCHAPv2)',
          text: 'The gateway is authenticated by its certificate (CA certificate and gateway identity required). EAP-MSCHAPv2 is weak; prefer a certificate if the gateway supports it.',
        },
        {
          term: 'Virtual IP',
          text: 'The gateway assigns an address to this device; it is the VPN IP, and LAN devices are masqueraded behind it as with OpenVPN.',
        },
        {
          term: 'Net-to-net',
          text: 'Local subnets of your LAN are connected to the remote subnets with their own addresses. Your LAN router needs a static route for the remote subnets with this device as gateway; the form shows the address to use.',
        },
      ],
    },
    {
      type: 'list',
      items: [
        'IKEv1 is only a fallback for gateways without IKEv2, such as the FRITZ!Box user access: Aggressive Mode with pre-shared key and XAuth. IKEv1 is deprecated (RFC 9395), and Aggressive Mode sends the identity unencrypted and lets an eavesdropper guess the pre-shared key offline. The profile and the Dashboard therefore show a security warning; use IKEv2 or WireGuard where possible.',
        'FRITZ!Box user access: in the FRITZ!Box under Internet → Permit Access → VPN (IPSec) open the user and the "VPN-Daten". Server → Gateway address, IPSec-ID → Local identity, shared secret → Pre-shared key, account and password → XAuth username and XAuth password.',
        'When the connection fails, the Dashboard names the reason: the gateway accepted none of the proposals (compare the IKE and ESP proposals), refused the subnets (compare local and remote subnets on both sides), assigned no virtual IP, or rejected the credentials.',
      ],
    },
    { type: 'link', target: 'migrate-from-rut240', text: 'Moving from a Teltonika RUT240' },
  ],
  connecting: [
    {
      type: 'paragraph',
      text: 'Connect on the Dashboard. With more than one profile, choose the profile next to "Connect".',
    },
    {
      type: 'terms',
      items: [
        { term: 'Disconnected', text: 'No tunnel. The firewall still protects this device.' },
        { term: 'Connecting', text: 'OpenVPN is reaching the server and signing in.' },
        {
          term: 'Connected',
          text: 'The tunnel is up; the Dashboard shows the VPN address and traffic.',
        },
        {
          term: 'Reconnecting',
          text: 'The connection was lost or is being renewed, for example by the daily reconnect.',
        },
        { term: 'Disconnecting', text: 'The tunnel is being closed.' },
        {
          term: 'Error',
          text: 'The last attempt failed. The Dashboard shows the reason and "Try again"; the Log page has the details.',
        },
      ],
    },
    {
      type: 'list',
      items: [
        'After network errors TunnelDeck-VPN retries on its own: first after 2 seconds, then doubling up to 60 seconds, without ever giving up.',
        'When the server rejects the credentials, retrying stops at once, so the provider does not lock the account. Correct username or password in the profile and connect again.',
        'After a container restart the profile that was connected connects again.',
        'A profile can always be deleted, also the active one: it is disconnected first (up to 15 seconds), then deleted. The confirmation says so.',
        'The Encryption row on the Dashboard shows the data-channel cipher the server negotiated; an unencrypted channel is shown in red.',
      ],
    },
  ],
  firewall: [
    {
      type: 'paragraph',
      text: 'Everything between the VPN and the local LAN is blocked in both directions unless a rule allows it. Replies to allowed connections always pass. Rules apply from top to bottom; change the order with the arrow buttons. Changes take effect with "Save changes".',
    },
    {
      type: 'terms',
      items: [
        {
          term: 'Inbound from VPN',
          text: 'Traffic arriving at the VPN address. The destination is exactly one IPv4 address in the local LAN.',
        },
        {
          term: 'This device or port forward',
          text: "The destination address decides: this device's own LAN address opens a port on this device (allow, drop or reject); any other LAN address makes the rule a port forward, which always allows. This is decided again on every apply, so reserve this device's address in your router.",
        },
        {
          term: 'Outbound to VPN',
          text: 'Lets a LAN device or subnet reach networks behind the VPN, with the VPN address as sender. The device must use this device as its gateway, or have a route to the destination via this device. Kill switch: while the tunnel is down this traffic is dropped and never leaves through the normal internet connection.',
        },
        {
          term: 'Sender seen by the device',
          text: '"This device" (default): the target sees this device as sender and answers it without route changes. "Original sender": the target sees the real remote address and must send its replies back through this device, for example with an outbound rule. Needed where the address matters, such as IPsec.',
        },
        {
          term: 'IPsec router',
          text: 'The card creates the rules for an IPsec router in the LAN: IKE (UDP 500 and 4500) and ESP forwarded to the router with the original sender kept, and an outbound rule for the router. Its default gateway must be this device.',
        },
        {
          term: 'Any port',
          text: 'An empty port field means any port. A port forward without a port forwards every port of its protocol, except the web UI port and, while remote access is on, its port.',
        },
        {
          term: 'Protections',
          text: 'Drop invalid packets, clamp TCP MSS, SYN flood protection (25 new connections per second per sender) and ping limit (5 per second), all on by default. "Global limit only" or "Not available on this system" means the host kernel lacks a module; see System checks.',
        },
        {
          term: 'Hit counters',
          text: 'How many new connections a rule matched since it last changed; "–" while the rule is off. Missing when the kernel lacks `xt_comment`.',
        },
      ],
    },
    {
      type: 'paragraph',
      text: 'The web UI port can never be opened to the tunnel, and the remote-access port is reserved. Port forwards and outbound rules need IP forwarding on the host (check `ip-forward`).',
    },
    {
      type: 'link',
      target: 'linux',
      text: 'Firewall concepts and IPsec example (Linux guide, section 10)',
    },
  ],
  'remote-access': [
    {
      type: 'paragraph',
      text: 'Remote access makes this web UI reachable through the VPN, over HTTPS only (default port 8443, freely selectable). The HTTP port 8194 stays closed on the tunnel. Turn it on under System → Remote access.',
    },
    {
      type: 'list',
      items: [
        'Keep the self-signed certificate or upload your own certificate and key (PEM).',
        'On the first visit the browser warns about a self-signed certificate. Compare its SHA-256 fingerprint with the one on the System page and continue only if they match.',
        'The sign-in page becomes reachable from the internet: use a long admin password.',
        'Remote access covers this web UI only. Other ports need a rule on the Firewall page.',
      ],
    },
    { type: 'subheading', text: 'Public address, not the VPN server address' },
    {
      type: 'paragraph',
      text: 'A common mix-up: the server address in the profile (for example `vpn.example.net`) is where this device connects to. It does not lead back to this device. Remote access uses the address of this end of the tunnel: the public address from the profile; without one, the public IP detected through the tunnel; and without that, the VPN address shown on the Dashboard. The System page shows the complete URL.',
    },
  ],
  'system-checks': [
    {
      type: 'paragraph',
      text: 'The System page lists the self-check run at every start. OK: in place. Warning: an optional module is missing, only the named feature is reduced and the firewall still works. Failure: a requirement is missing; fix it first. Restart the container after loading a kernel module.',
    },
    {
      type: 'terms',
      items: [
        { term: 'TUN device (`tun-device`)', text: 'Required. Without it no tunnel can start.' },
        {
          term: 'iptables (`iptables`)',
          text: 'Required. Without it there is no firewall and no kill switch.',
        },
        { term: 'ip tool (`ip`)', text: 'Required. Without it no routing for the tunnel.' },
        {
          term: 'NET_ADMIN capability (`net-admin`)',
          text: 'Required. Without it the container may not change firewall or routes.',
        },
        {
          term: 'IP forwarding (`ip-forward`)',
          text: 'Required for rules to other devices and outbound rules; rules to this device work without it.',
        },
        {
          term: 'LAN subnets (`lan-subnets`)',
          text: 'Required. Without them inbound rules to other LAN devices have no target.',
        },
        {
          term: 'Hit counters (`rule-counters`)',
          text: 'Optional. Without `xt_comment` the counters are off.',
        },
        {
          term: 'SYN flood protection (`syn-flood-protection`)',
          text: 'Optional. A global instead of a per-sender rate, or left out.',
        },
        {
          term: 'Ping limit (`ping-limit`)',
          text: 'Optional. Left out only when both rate modules are missing.',
        },
        {
          term: 'TCP MSS clamping (`mss-clamp`)',
          text: 'Optional. Without `xt_TCPMSS` large transfers may stall.',
        },
        {
          term: 'REJECT target (`reject-target`)',
          text: 'Optional. Reject rules drop silently instead.',
        },
        {
          term: 'Reply routing of port forwards (`reply-routing`)',
          text: 'Optional. Without CONNMARK a port-forward target that uses this device as gateway sends all its traffic through the tunnel.',
        },
      ],
    },
    {
      type: 'link',
      target: 'system-checks',
      text: 'Every check in detail, with fixes for Linux and DSM',
    },
  ],
  'sign-ins': [
    {
      type: 'paragraph',
      text: 'The "Sign-ins" tab on the Log page lists sign-ins, sign-outs and the requests TunnelDeck-VPN blocked, newest first, with the time, the IP address and the access (LAN or Remote). It keeps the last 500 sign-ins and sign-outs and, separately, the last 500 security events, so a burst of attacks never pushes the sign-ins out. Attempted usernames, passwords and request contents are never recorded.',
    },
    {
      type: 'terms',
      items: [
        {
          term: 'Wrong username or password',
          text: 'A failed sign-in. Single ones are usually typing errors.',
        },
        {
          term: 'Blocked: waiting time, remote sign-in locked',
          text: 'Sign-in attempts during the waiting time after failed ones, or while remote sign-in is locked for everyone. Repeated attempts are counted in one entry.',
        },
        {
          term: 'Blocked: cross-site or scripted request',
          text: 'A change request without the header the web UI always sends, or from a foreign web page. Browsers using this UI never cause it; another web page or a script did.',
        },
        {
          term: 'Blocked: request too large, malformed request',
          text: 'A request body over 1 MiB or not the JSON the web UI sends.',
        },
        {
          term: 'Possible scan',
          text: 'Ten or more requests for API addresses that do not exist from one address within a minute, counted in one entry.',
        },
      ],
    },
    {
      type: 'paragraph',
      text: 'A red banner counts the blocked attempts of the last 24 hours. A yellow notice appears when the latest sign-in came over remote access from an address no earlier sign-in used: if that was not you, sign out everywhere and reset the admin password.',
    },
  ],
  troubleshooting: [
    {
      type: 'paragraph',
      text: 'Start on the Log page: choose "Warnings and errors" and copy the relevant lines when you ask for help.',
    },
    {
      type: 'terms',
      items: [
        {
          term: 'Warnings about `cipher none`',
          text: 'OpenVPN warns about an unencrypted data channel when the profile\'s cipher is `none`. That is expected for providers without encryption. The log notes that the warning comes from the profile setting; the "Data Channel:" line names the cipher in use.',
        },
        {
          term: '"Options error … [PUSH-OPTIONS]"',
          text: 'Older versions logged this for every route or DNS option the server pushed. Pushed routes and DNS options are now filtered and the message no longer appears. If you still see it, update the image.',
        },
        {
          term: 'Missing kernel modules',
          text: 'Warnings or failures on the System page name the module. Load it on the host and restart the container; see the System checks guide.',
        },
        {
          term: 'Stalled connections, MTU',
          text: 'Small requests work but large transfers hang, often when another VPN such as IPsec runs inside this tunnel or this tunnel inside another one. Keep "Clamp TCP MSS" on and lower the MTU or TCP MSS of the inner connection, for example on the IPsec router. Use `tun-mtu` or `mssfix` in the extra options only when your provider asks for it.',
        },
        {
          term: 'Routing warning',
          text: '"Routing for forwarded traffic could not be applied; retrying…" on the Dashboard: the tunnel stays up and the routing is retried automatically. The log names the failing `ip` command. If it persists, check `ip` and `net-admin` on the System page.',
        },
        {
          term: 'Credentials rejected',
          text: 'The connection stops in the error state without retrying. Correct username or password in the profile, then connect.',
        },
      ],
    },
    { type: 'link', target: 'issues', text: 'Report a problem on GitHub' },
  ],
  'admin-reset': [
    {
      type: 'paragraph',
      text: 'If the admin password is lost, reset the admin account. This removes the account and ends every session; profiles, firewall rules, settings and certificates stay, and a connected tunnel stays connected. The next visit shows the setup page.',
    },
    {
      type: 'list',
      items: [
        'With a shell on the Docker host: `docker exec tunneldeck tunneldeck reset-admin`.',
        'Without a shell: set `TUNNELDECK_RESET_ADMIN: "1"` in the compose file, recreate the container and create the new account. Then remove the variable and recreate the container again; otherwise every restart deletes the account.',
      ],
    },
    { type: 'link', target: 'reset-admin', text: 'Lost admin password: the full guide' },
  ],
};
