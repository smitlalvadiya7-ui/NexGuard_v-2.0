from pathlib import Path


def decode_qr_image(file_path):
    # Try OpenCV QRCodeDetector first because it does not need external zbar DLL.
    try:
        import cv2
        image = cv2.imread(str(file_path))
        detector = cv2.QRCodeDetector()
        data, _, _ = detector.detectAndDecode(image)
        if data:
            return data
    except Exception:
        pass

    # Optional pyzbar fallback.
    try:
        from pyzbar.pyzbar import decode
        from PIL import Image
        decoded = decode(Image.open(str(file_path)))
        if decoded:
            return decoded[0].data.decode("utf-8", errors="ignore")
    except Exception:
        pass
    return ""
