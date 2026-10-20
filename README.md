# CyberScope

Разведочный инструмент: сканирует порты через Nmap, перебирает поддомены по DNS и сохраняет HTML-отчёт.

Использовать только на системах, на тестирование которых есть письменное разрешение.

## Требования

- Python 3.10+
- [Nmap](https://nmap.org/download.html) в `PATH`

## Запуск

```powershell
python -m cyberscope 192.168.1.10 --ports 22,80,443 --i-have-permission
python -m cyberscope example.com --domain example.com --ports 80,443 --out report.html --i-have-permission
```

Без `--i-have-permission` скан не запускается.

## Тесты

```powershell
python -m unittest discover -s tests -v
```
