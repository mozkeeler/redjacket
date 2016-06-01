self.port.on("revoked", function(revocation) {
  let revocations = document.getElementById("revocations");
  let li = document.createElement("li");
  li.textContent = revocation.displayName;
  li.ondblclick = handleRemove.bind({}, revocation, li);
  revocations.appendChild(li);
  doResize();
});

function handleRemove(revocation, li) {
  window.getSelection().removeAllRanges();
  li.setAttribute("class", "removed");
  self.port.emit("remove", revocation);
  let restartText = document.getElementById("restart");
  restartText.setAttribute("class", "");
  doResize();
}

self.port.on("triggerResize", doResize);

function doResize() {
  let container = document.getElementById("container");
  self.port.emit("resize", { width: container.scrollWidth + 20, // padding or something
                             height: container.scrollHeight + 20 });
}

function depemify(pem) {
  return pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "")
            .replace(/[\r\n]/g, "");
}

function base64ToArray(base64) {
  let binString = atob(base64);
  let array = [];
  for (let i = 0; i < binString.length; i++) {
    array.push(binString.charCodeAt(i));
  }
  return array;
}

function arrayToBase64(array) {
  let str = "";
  for (let n of array) {
    str += String.fromCharCode(n);
  }
  return btoa(str);
}

function getAndPopLength(der) {
  if (!der || der.length < 1) {
    return null;
  }
  if (der[0] < 0x80) {
    let len = der.shift();
    if (der.length < len) {
      return null;
    }
    return len;
  }
  if (der[0] == 0x80) {
    return null;
  }
  if (der[0] == 0x81) {
    if (der.length < 2) {
      return null;
    }
    der.shift();
    let len = der.shift();
    if (der.length < len || len < 0x80) {
      return null;
    }
    return len;
  }
  if (der[0] == 0x82) {
    if (der.length < 3) {
      return null;
    }
    der.shift();
    let len = (der.shift() << 8) + der.shift();
    if (der.length < len) {
      return null;
    }
    return len;
  }
  return null;
}

function getTLV(der, expectedTag) {
	if (!der || der.length < 1 || der[0] != expectedTag) {
		return null;
	}
  let contents = der.slice(1);// NB: slice returns a (modified) copy of der
  let len = getAndPopLength(contents);
  let tagAndLengthBytes = der.length - contents.length;
  if (tagAndLengthBytes < 0 || tagAndLengthBytes > 4) {
    return null;
  }
  return der.slice(0, tagAndLengthBytes + len);
}

function getContents(der, expectedTag) {
	if (!der || der.length < 1 || der[0] != expectedTag) {
		return null;
	}
  der.shift();
  let len = getAndPopLength(der);
  if (!len) { // TODO: well, so technically the length could be 0...
    return null;
  }
  return der.slice(0, len);
}

function skip(der, expectedTag) {
	if (!der || der.length < 1 || der[0] != expectedTag) {
		return null;
	}
  der.shift();
  let len = getAndPopLength(der);
  if (!len) { // TODO: well, so technically the length could be 0...
    return null;
  }
  return der.slice(len);
}

// From RFC 5280:
//
// Certificate  ::=  SEQUENCE  {
//      tbsCertificate       TBSCertificate,
//      ...
//
// TBSCertificate  ::=  SEQUENCE  {
//      version         [0]  EXPLICIT Version DEFAULT v1,
//      serialNumber         CertificateSerialNumber,
//      signature            AlgorithmIdentifier,
//      issuer               Name,
//      validity             Validity,
//      subject              Name,
//      ...
//
// CertificateSerialNumber  ::=  INTEGER
//
// AlgorithmIdentifier  ::=  SEQUENCE  {
//      ...
//
// Name ::= CHOICE { -- only one possibility for now --
//   rdnSequence  RDNSequence }
//
// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
//
// Validity ::= SEQUENCE {
//      ...
//
function getSubject(derArray) {
  const SEQUENCE = 0x30;
  const INTEGER = 0x02;
  const CONTEXT_SPECIFIC = 2 << 6;
  const CONSTRUCTED = 1 << 5;

  let certificateContents = getContents(derArray, SEQUENCE);
  if (!certificateContents) {
    return null;
  }
  let tbsCertificateContents = getContents(certificateContents, SEQUENCE);
  if (!tbsCertificateContents) {
    return null;
  }
  let reader = skip(tbsCertificateContents, CONTEXT_SPECIFIC | CONSTRUCTED | 0); // version
  if (!reader) {
    return null;
  }
  reader = skip(reader, INTEGER); // serialNumber
  if (!reader) {
    return null;
  }
  reader = skip(reader, SEQUENCE); // signature
  if (!reader) {
    return null;
  }
  reader = skip(reader, SEQUENCE); // issuer
  if (!reader) {
    return null;
  }
  reader = skip(reader, SEQUENCE); // validity
  if (!reader) {
    return null;
  }
  let subject = getTLV(reader, SEQUENCE);
  return arrayToBase64(subject);
}

function doDistrust() {
  let intermediateTextArea = document.getElementById("intermediateTextArea");
  let base64 = depemify(intermediateTextArea.value);
  let bytes = base64ToArray(base64);
  self.port.emit("distrust", { base64: base64, subject: getSubject(bytes),
                               fromStorage: false });
}

var distrustButton = document.getElementById("distrustButton");
distrustButton.onclick = doDistrust;

function handleFiles() {
  self.port.emit("openPanel");
  let filePicker = document.getElementById("filePicker");
  let reader = new FileReader();
  reader.addEventListener("loadend", function() {
    let intermediateTextArea = document.getElementById("intermediateTextArea");
    intermediateTextArea.value = reader.result;
    doDistrust();
  });
  reader.readAsText(filePicker.files[0]);
}

var filePicker = document.getElementById("filePicker");
filePicker.onchange = handleFiles;
