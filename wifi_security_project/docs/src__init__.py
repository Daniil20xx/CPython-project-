"""
src/ — Основной пакет проекта WiFi Security Educational Toolkit
================================================================
Содержит три подпакета:

  wep/       — RC4-шифрование и атаки на протокол WEP
  wpa/       — Криптографическая цепочка WPA/WPA2 и словарные атаки
  benchmark/ — Сравнительный бенчмарк скоростей атак

Импорт:
    from src.wep.wep_crypto import wep_encrypt, wep_decrypt
    from src.wpa.wpa_crypto import compute_pmk, verify_password
    from src.benchmark.benchmark import benchmark_wep, benchmark_wpa2_full
"""
