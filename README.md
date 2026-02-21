# Nebula Messenger

Локальный мессенджер на Flask + SQLite: регистрация/вход, личные сообщения, каналы, админ-панель, SSE realtime, загрузка аватаров.

## Стек
- Python 3.11+
- Flask
- SQLite

## Локальный запуск
```powershell
python -m pip install -r requirements.txt
python app.py
```
Или:
```powershell
.\start.ps1
```
Открой: `http://127.0.0.1:5000`

## Подготовка к GitHub
```powershell
git init
git add .
git commit -m "Initial Nebula messenger"
git branch -M main
git remote add origin https://github.com/<your-user>/<your-repo>.git
git push -u origin main
```

## Деплой из GitHub
GitHub Pages не подходит (проект серверный). Используй Render/Railway/Fly.

### Render (рекомендуется)
1. Подключи репозиторий GitHub.
2. Тип сервиса: `Web Service`.
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn -w 2 -b 0.0.0.0:$PORT wsgi:app`
5. Добавь ENV:
   - `NEBULA_JWT_SECRET`
   - `NEBULA_MSG_SECRET`

## Важные файлы
- `app.py` — backend API и БД
- `templates/index.html` — UI
- `static/app.js` — frontend логика
- `static/styles.css` — стили
- `Procfile`, `wsgi.py`, `runtime.txt` — прод-запуск

## Примечания
- База по умолчанию: `data/nebula.db`
- Загрузки аватаров: `static/uploads/`
- Первый зарегистрированный пользователь автоматически получает `admin`.
