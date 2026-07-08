from src.detection_engine import detect_threat

attack_messages = [
    "تم ايقاف حسابك اضغط الرابط الآن",
    "اربح 1000$ الآن 💰 اضغط هنا",
    "اذا ما دفعت رح انشر صورك",
    "انا من البنك اعطني رمز OTP",
    "ادخل hxxp://fake-link لتحديث بياناتك",
    "ا د خ ل ا ل ر ا ب ط ا ل ا ت ي"
]

for msg in attack_messages:
    print("\n=== RED TEAM ATTACK ===")
    result = detect_threat(msg)
    for k, v in result.items():
        print(f"{k}: {v}")
    print("-" * 60)
