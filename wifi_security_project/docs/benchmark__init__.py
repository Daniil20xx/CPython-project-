"""
src/benchmark/ — Пакет сравнительного бенчмарка
================================================
Измеряет и сравнивает скорости атак на WEP, WPA и WPA2.

Файлы:
  benchmark.py — Четыре бенчмарка + итоговая таблица с оценкой риска:
                  benchmark_wep()          → RC4+CRC32 (100k–1M кл/с)
                  benchmark_wpa()          → HMAC-MD5 MIC (10k–50k чек/с)
                  benchmark_wpa2_full()    → полный PBKDF2-pipeline (300–2k пар/с)
                  benchmark_pbkdf2()       → чистый PBKDF2 (300–800 вычислений/с)

Запуск:
    cd wifi_security_project
    python src/benchmark/benchmark.py           # 3s на тест
    python src/benchmark/benchmark.py --quick   # 2s на тест
    python src/benchmark/benchmark.py --full    # 10s на тест (точнее)
"""
