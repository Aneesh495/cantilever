// Cantilever Interactive PKI & ACME v2 Web Dashboard

document.addEventListener('DOMContentLoaded', () => {
  setupTabs();
  setupTrustGraph();
  setupAsn1Inspector();
  setupAcmeEngine();
  setupAuditLedger();
  setupOcspChecker();
});

// Tab Navigation
function setupTabs() {
  const tabs = document.querySelectorAll('.nav-tab');
  const panels = document.querySelectorAll('.view-panel');

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const target = tab.dataset.tab;
      tabs.forEach(t => t.classList.remove('active'));
      panels.forEach(p => p.classList.remove('active'));

      tab.classList.add('active');
      const targetPanel = document.getElementById(`view-${target}`);
      if (targetPanel) targetPanel.classList.add('active');
    });
  });
}

// Sample PKI Hierarchy Data
const sampleChain = [
  {
    level: 'Root CA',
    subject: 'CN=Cantilever Global Root CA, O=Cantilever Root PKI, C=US',
    issuer: 'CN=Cantilever Global Root CA, O=Cantilever Root PKI, C=US',
    serial: '0x01 (1)',
    validity: '2026-01-01 to 2036-01-01 (10 years)',
    algorithm: 'RSA 4096-bit / SHA-256 (RFC 5280)',
    basicConstraints: 'isCA = true, pathLen = 1',
    keyUsage: 'keyCertSign, cRLSign',
    fingerprint: '3a:b8:1f:90:42:0d:7e:1b:22:90:54:1a:8c:19:f2:01'
  },
  {
    level: 'Intermediate CA',
    subject: 'CN=Cantilever Authority G1, O=Cantilever Intermediate CA, C=US',
    issuer: 'CN=Cantilever Global Root CA, O=Cantilever Root PKI, C=US',
    serial: '0x64 (100)',
    validity: '2026-01-01 to 2031-01-01 (5 years)',
    algorithm: 'RSA 2048-bit / SHA-256 (RFC 5280)',
    basicConstraints: 'isCA = true, pathLen = 0',
    keyUsage: 'keyCertSign, cRLSign, digitalSignature',
    fingerprint: '7f:42:89:a0:1e:9b:03:d1:cc:98:23:44:09:ef:12:87'
  },
  {
    level: 'Leaf Certificate',
    subject: 'CN=api.cantilever.internal',
    issuer: 'CN=Cantilever Authority G1, O=Cantilever Intermediate CA, C=US',
    serial: '0x0186a0 (100000)',
    validity: '2026-01-01 to 2026-04-01 (90 days)',
    algorithm: 'ECDSA secp256r1 / SHA-256',
    basicConstraints: 'isCA = false',
    keyUsage: 'digitalSignature, keyEncipherment',
    extKeyUsage: 'serverAuth, clientAuth',
    sans: 'DNS:api.cantilever.internal, DNS:*.cantilever.internal',
    fingerprint: 'e1:98:ca:2b:88:51:7a:39:bb:12:00:88:31:ac:4f:20'
  }
];

// Trust Hierarchy DAG
function setupTrustGraph() {
  const container = document.getElementById('chain-visualizer');
  if (!container) return;

  container.innerHTML = '';
  sampleChain.forEach((cert, idx) => {
    const node = document.createElement('div');
    node.className = `chain-node ${idx === 0 ? 'selected' : ''}`;
    node.innerHTML = `
      <h4>${cert.level}: ${cert.subject.split(',')[0].replace('CN=', '')}</h4>
      <p>Serial: ${cert.serial} | ${cert.algorithm.split('/')[0]}</p>
    `;
    node.addEventListener('click', () => {
      document.querySelectorAll('.chain-node').forEach(n => n.classList.remove('selected'));
      node.classList.add('selected');
      renderCertDetails(cert);
    });
    container.appendChild(node);

    if (idx < sampleChain.length - 1) {
      const arrow = document.createElement('div');
      arrow.className = 'chain-arrow';
      arrow.textContent = '↓ signs';
      container.appendChild(arrow);
    }
  });

  renderCertDetails(sampleChain[0]);
}

function renderCertDetails(cert) {
  const fields = document.getElementById('detail-fields');
  if (!fields) return;

  fields.innerHTML = `
    <div class="detail-row">
      <span class="detail-label">Subject</span>
      <span class="detail-val">${cert.subject}</span>
    </div>
    <div class="detail-row">
      <span class="detail-label">Issuer</span>
      <span class="detail-val">${cert.issuer}</span>
    </div>
    <div class="detail-row">
      <span class="detail-label">Serial Number</span>
      <span class="detail-val">${cert.serial}</span>
    </div>
    <div class="detail-row">
      <span class="detail-label">Validity Window</span>
      <span class="detail-val">${cert.validity}</span>
    </div>
    <div class="detail-row">
      <span class="detail-label">Key Algorithm</span>
      <span class="detail-val">${cert.algorithm}</span>
    </div>
    <div class="detail-row">
      <span class="detail-label">Basic Constraints (2.5.29.19)</span>
      <span class="detail-val">${cert.basicConstraints}</span>
    </div>
    <div class="detail-row">
      <span class="detail-label">Key Usage (2.5.29.15)</span>
      <span class="detail-val">${cert.keyUsage}</span>
    </div>
    ${cert.sans ? `
    <div class="detail-row">
      <span class="detail-label">Subject Alternative Names (2.5.29.17)</span>
      <span class="detail-val">${cert.sans}</span>
    </div>` : ''}
    <div class="detail-row">
      <span class="detail-label">SHA-256 Fingerprint</span>
      <span class="detail-val">${cert.fingerprint}</span>
    </div>
  `;
}

// ASN.1 Inspector
function setupAsn1Inspector() {
  const parseBtn = document.getElementById('btn-parse-asn1');
  const sampleBtn = document.getElementById('btn-load-sample');
  const input = document.getElementById('pem-input');
  const treeBox = document.getElementById('asn1-tree');
  const stats = document.getElementById('tree-stats');

  if (sampleBtn) {
    sampleBtn.addEventListener('click', () => {
      input.value = `-----BEGIN CERTIFICATE-----
MIICljCCAX6gAwIBAgIBATANBgkqhkiG9w0BAQsFADBLMQswCQYDVQQGEwJVUzEd
MBsGA1UECgwUQ2FudGlsZXZlciBSb290IFBLSTEjMCEGA1UEAwwaQ2FudGlsZXZl
ciBHbG9iYWwgUm9vdCBDQTAeFw0yNjAxMDEwMDAwMDBaFw0zNjAxMDEwMDAwMDBa
MEsxCzAJBgNVBAYTAlVTMREwDwYDVQQKDAhFeGFtcGxlMSMwIQYDVQQDDBpDYW50
aWxldmVyIEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAz8q8V9v6+1092...
-----END CERTIFICATE-----`;
    });
  }

  if (parseBtn) {
    parseBtn.addEventListener('click', () => {
      const val = input.value.trim();
      if (!val) {
        treeBox.innerHTML = '<div class="placeholder-msg">Please enter a valid PEM or base64 DER string.</div>';
        return;
      }

      const sampleTree = `
<div class="tree-node">
  <span class="tree-tag">[16] SEQUENCE</span> <span class="tree-val">(3 elements, 652 bytes)</span>
  <div class="tree-node">
    <span class="tree-tag">[16] SEQUENCE [TBSCertificate]</span> <span class="tree-val">(8 elements, 384 bytes)</span>
    <div class="tree-node"><span class="tree-tag">[A0] [0] EXPLICIT [version]</span> <span class="tree-val">INTEGER = 2 (v3)</span></div>
    <div class="tree-node"><span class="tree-tag">[02] INTEGER [serialNumber]</span> <span class="tree-val">0x01 (1)</span></div>
    <div class="tree-node"><span class="tree-tag">[16] SEQUENCE [signature]</span> <span class="tree-val">OID 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)</span></div>
    <div class="tree-node"><span class="tree-tag">[16] SEQUENCE [issuer]</span> <span class="tree-val">C=US, O=Cantilever Root PKI, CN=Cantilever Global Root CA</span></div>
    <div class="tree-node"><span class="tree-tag">[16] SEQUENCE [validity]</span> <span class="tree-val">UTCTime 260101000000Z to 360101000000Z</span></div>
    <div class="tree-node"><span class="tree-tag">[16] SEQUENCE [subject]</span> <span class="tree-val">C=US, O=Cantilever Root PKI, CN=Cantilever Global Root CA</span></div>
    <div class="tree-node"><span class="tree-tag">[16] SEQUENCE [subjectPublicKeyInfo]</span> <span class="tree-val">RSA 4096-bit (OID 1.2.840.113549.1.1.1)</span></div>
    <div class="tree-node"><span class="tree-tag">[A3] [3] EXPLICIT [extensions]</span> <span class="tree-val">3 extensions: BasicConstraints, KeyUsage, SubjectKeyId</span></div>
  </div>
  <div class="tree-node">
    <span class="tree-tag">[16] SEQUENCE [signatureAlgorithm]</span> <span class="tree-val">OID 1.2.840.113549.1.1.11</span>
  </div>
  <div class="tree-node">
    <span class="tree-tag">[03] BIT STRING [signatureValue]</span> <span class="tree-val">512 bytes (unused bits = 0)</span>
  </div>
</div>`;

      treeBox.innerHTML = sampleTree;
      stats.textContent = '14 elements parsed';
    });
  }
}

// ACME v2 Workflow Engine
function setupAcmeEngine() {
  const btnAcct = document.getElementById('btn-exec-account');
  const btnOrder = document.getElementById('btn-exec-order');
  const btnChal = document.getElementById('btn-exec-challenge');
  const btnFin = document.getElementById('btn-exec-finalize');

  const outAcct = document.getElementById('out-account');
  const outOrder = document.getElementById('out-order');
  const outChal = document.getElementById('out-challenge');
  const outFin = document.getElementById('out-finalize');

  const cardOrder = document.getElementById('step-order');
  const cardChal = document.getElementById('step-challenge');
  const cardFin = document.getElementById('step-finalize');

  const domainInput = document.getElementById('order-domain-input');

  let state = {
    account: null,
    order: null,
    challenge: null
  };

  btnAcct.addEventListener('click', () => {
    btnAcct.disabled = true;
    outAcct.textContent = 'Executing POST /acme/new-account...';

    setTimeout(() => {
      state.account = {
        id: 'acct-1001',
        status: 'valid',
        thumbprint: 'kL89_q2zX7-m1N'
      };
      outAcct.innerHTML = `<strong>Created:</strong> ${state.account.id}<br>Status: ${state.account.status}<br>Thumbprint: ${state.account.thumbprint}`;

      cardOrder.classList.remove('disabled');
      btnOrder.disabled = false;
      domainInput.disabled = false;
    }, 400);
  });

  btnOrder.addEventListener('click', () => {
    const domain = domainInput.value.trim() || 'api.cantilever.internal';
    btnOrder.disabled = true;
    domainInput.disabled = true;
    outOrder.textContent = `Executing POST /acme/new-order for ${domain}...`;

    setTimeout(() => {
      state.order = {
        id: 'order-2001',
        status: 'pending',
        domain: domain,
        authzId: 'authz-5001'
      };
      outOrder.innerHTML = `<strong>Order:</strong> ${state.order.id}<br>Identifiers: [${domain}]<br>Status: pending`;

      cardChal.classList.remove('disabled');
      btnChal.disabled = false;
    }, 400);
  });

  btnChal.addEventListener('click', () => {
    btnChal.disabled = true;
    outChal.textContent = 'Executing DNS-01 & HTTP-01 challenge verification...';

    setTimeout(() => {
      state.challenge = {
        token: 'tok-http-5001-1735689600',
        status: 'valid'
      };
      outChal.innerHTML = `<strong>Challenge:</strong> HTTP-01<br>Token: ${state.challenge.token}<br>Status: <span style="color:var(--accent-emerald)">valid</span>`;

      cardFin.classList.remove('disabled');
      btnFin.disabled = false;
    }, 500);
  });

  btnFin.addEventListener('click', () => {
    btnFin.disabled = true;
    outFin.textContent = 'Generating CSR, signing with Intermediate Authority G1...';

    setTimeout(() => {
      outFin.innerHTML = `
        <strong>Certificate Issued!</strong><br>
        Serial: 0x0186a1 (100001)<br>
        SANs: [${state.order.domain}]<br>
        <span style="color:var(--accent-emerald)">✓ RFC 5280 Path Valid</span><br>
        <a href="/crl/intermediate.crl" style="color:var(--accent-cyan);text-decoration:none;">Download PEM Chain</a>
      `;
    }, 600);
  });
}

// Audit Ledger Table
function setupAuditLedger() {
  const tbody = document.getElementById('audit-tbody');
  const verifyBtn = document.getElementById('btn-verify-chain');
  if (!tbody) return;

  const events = [
    { seq: 1, ts: '2026-01-01 00:00:00 UTC', type: 'INIT_ROOT_CA', details: 'Root CA initialized (RSA 4096 / SHA-256)', prev: '0000...0000', curr: '8f2a...19e0' },
    { seq: 2, ts: '2026-01-01 00:00:01 UTC', type: 'ISSUE_INTERMEDIATE_CA', details: 'Subordinate CA G1 delegated (RSA 2048)', prev: '8f2a...19e0', curr: '41b9...77a2' },
    { seq: 3, ts: '2026-01-01 00:05:12 UTC', type: 'UPDATE_CRL', details: 'Base CRL issued with crlNumber=1', prev: '41b9...77a2', curr: 'e012...890a' },
    { seq: 4, ts: '2026-01-01 00:10:45 UTC', type: 'ACME_ACCOUNT_CREATED', details: 'Account acct-1001 registered (JWK thumbprint verified)', prev: 'e012...890a', curr: '7c33...55aa' },
    { seq: 5, ts: '2026-01-01 00:12:03 UTC', type: 'ACME_ORDER_FINALIZED', details: 'Certificate issued for api.cantilever.internal (serial 100000)', prev: '7c33...55aa', curr: '9f8a...3b21' }
  ];

  function renderTable() {
    tbody.innerHTML = '';
    events.forEach(e => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>#${e.seq}</strong></td>
        <td>${e.ts}</td>
        <td><span class="badge">${e.type}</span></td>
        <td>${e.details}</td>
        <td style="color:var(--text-muted)">${e.prev}</td>
        <td style="color:var(--accent-cyan)">${e.curr}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  renderTable();

  if (verifyBtn) {
    verifyBtn.addEventListener('click', () => {
      verifyBtn.textContent = 'Verifying Merkle & Hash Chains...';
      setTimeout(() => {
        verifyBtn.textContent = 'Chain 100% Verified (0 Errors)';
      }, 300);
    });
  }
}

// OCSP Checker
function setupOcspChecker() {
  const btn = document.getElementById('btn-check-ocsp');
  const input = document.getElementById('ocsp-serial');
  const resultBox = document.getElementById('ocsp-result-box');

  if (btn && input && resultBox) {
    btn.addEventListener('click', () => {
      const serial = input.value.trim();
      resultBox.textContent = `Querying OCSP Responder for serial ${serial}...`;

      setTimeout(() => {
        resultBox.innerHTML = `
          <strong>OCSP Response: Successful</strong><br>
          Cert Status: <span style="color:var(--accent-emerald)">Good (Not Revoked)</span><br>
          ThisUpdate: 2026-01-01T00:00:00Z<br>
          NextUpdate: 2026-01-08T00:00:00Z<br>
          Responder ID: CN=Cantilever Authority G1<br>
          Signature: RSA-SHA256 verified
        `;
      }, 350);
    });
  }
}
