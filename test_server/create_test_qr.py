import qrcode

url = "https://google-security-example.com/login"

qr = qrcode.make(url)
qr.save("impersonation_test_qr.png")

print("QR created")