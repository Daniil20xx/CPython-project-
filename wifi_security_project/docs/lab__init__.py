"""
lab/ — Лабораторные работы
===========================
Практические задания для изучения криптографии WiFi.

Файлы:
  aes_demo.py  — Пошаговая демонстрация AES-128: SubBytes, ShiftRows,
                 MixColumns, AddRoundKey. Проверка на NIST-векторах.
  aes_crack.py — Учебная словарная атака на WPA2 с визуализацией
                 каждого шага pipeline и анализом стойкости паролей.

Порядок прохождения лабораторной:
  Шаг 1: python lab/aes_demo.py --verbose     # смотрим AES изнутри
  Шаг 2: python lab/aes_demo.py --test        # проверяем NIST-векторы
  Шаг 3: python lab/aes_crack.py --auto       # атака на WPA2
  Шаг 4: python lab/aes_crack.py --complexity-test  # анализ паролей
  Шаг 5: ответить на вопросы в отчёте (Q1–Q5 в aes_crack.py)
"""
