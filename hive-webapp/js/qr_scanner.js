import 'html5-qrcode/minified/html5-qrcode.min';

export function scan_qr() {
    var html5QrcodeScanner = new Html5QrcodeScanner(
        "reader", { fps: 10, qrbox: 250 }, true);

    function onScanSuccess(qrCodeMessage) {
        // handle on success condition with the decoded message
        html5QrcodeScanner.clear();
        // ^ this will stop the scanner (video feed) and clear the scan area.
    }

    html5QrcodeScanner.render(onScanSuccess);
};
