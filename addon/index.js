var panels = require("sdk/panel");
var self = require("sdk/self");
var ss = require("sdk/simple-storage");
var { Cc, Ci } = require("chrome");
var { ToggleButton } = require("sdk/ui/button/toggle");

var button = ToggleButton({
  id: "redjacket-button",
  label: "Red Jacket",
  icon: {
    16: "./icon-16.png",
    32: "./icon-32.png",
    64: "./icon-64.png"
  },
  onChange: handleChange
});

var panel = panels.Panel({
  contentURL: self.data.url("panel.html"),
  contentScriptFile: self.data.url("panel.js"),
  onShow: handleShow,
  onHide: handleHide
});

function handleChange(state) {
  if (state.checked) {
    panel.show({
      position: button,
    });
  }
}

panel.port.on("distrust", doDistrust);
panel.port.on("resize", doResize);

function doResize(size) {
  if (!panel.isShowing) {
    return;
  }
  panel.resize(size.width, size.height);
}

function formatDisplayName(cert) {
  if (cert.commonName) {
    return cert.commonName;
  }
  if (cert.organization) {
    return cert.organization;
  }
  if (cert.organizationalUnit) {
    return cert.organizationalUnit;
  }
  return cert.serialNumber;
}

function doDistrust(revocation) {
  if (!revocation.fromStorage && haveRevocation(revocation)) {
    return;
  }
  if (!revocation.base64 || !revocation.subject) {
    return;
  }
  let certDB = Cc["@mozilla.org/security/x509certdb;1"]
                 .getService(Ci.nsIX509CertDB);
  let cert;
  try {
    cert = certDB.constructX509FromBase64(revocation.base64);
  } catch (e) {
    return;
  }
  let certBlocklist = Cc["@mozilla.org/security/certblocklist;1"]
                        .getService(Ci.nsICertBlocklist);
  certBlocklist.revokeCertBySubjectAndPubKey(
    revocation.subject, cert.sha256SubjectPublicKeyInfoDigest);

  let result = certDB.verifyCertNow(cert, 0x08 /* certificateUsageSSLCA */, 0,
                                    null, {}, {});
  if (result == -8180) {
    console.log("successfully revoked");
  } else {
    console.log("unexpected verification result: " + result);
  }
  revocation.displayName = formatDisplayName(cert);
  if (!revocation.fromStorage) {
    saveRevocation(revocation);
  }
  panel.port.emit("revoked", revocation);
}

function haveRevocation(revocation) {
  if (!ss.storage.revocations) {
    return false;
  }
  return ss.storage.revocations.some(function(r) {
    return r.base64 == revocation.base64 && r.subject == revocation.subject;
  });
}

function saveRevocation(revocation) {
  if (!ss.storage.revocations) {
    ss.storage.revocations = [];
  }
  if (!haveRevocation(revocation)) {
    ss.storage.revocations.push(revocation);
  }
}

function handleShow() {
  panel.port.emit("triggerResize");
}

function handleHide() {
  button.state("window", { checked: false });
}

if (ss.storage.revocations) {
  ss.storage.revocations.forEach(function(revocation) {
    revocation.fromStorage = true;
    doDistrust(revocation);
  });
}

function removeRevocation(revocation) {
  if (!ss.storage.revocations) {
    return;
  }
  ss.storage.revocations = ss.storage.revocations.filter(function(r) {
    return !(r.base64 == revocation.base64 && r.subject == revocation.subject);
  });
}

panel.port.on("remove", removeRevocation);
panel.port.on("openPanel", function() {
  handleChange({ checked: true });
});
