# SVPlayerPatcher

Standalone iOS dylib для инспекции классов SVPlayer и патчинга Premium.

**Не требует CydiaSubstrate / Jailbreak.**

## Как использовать

1. Перейди в **Actions** → **Build iOS Dylib** → **Run workflow**
2. Дождись сборки (~1 мин)
3. Скачай `SVPlayerPatcher.dylib` из **Releases** или **Artifacts**
4. Вшей в SVPlayer.ipa через GBox/ESign
5. Запусти SVPlayer — через 3 секунды появится алерт со списком всех Premium-классов

## Что делает

- При загрузке сканирует все Objective-C классы приложения
- Фильтрует по ключевым словам: premium, subscription, purchase, pro, vip, license, paid
- Показывает найденные классы, их свойства и методы
- Сохраняет результат в файл `svplayer_classes.txt` в Documents
- Копирует результат в буфер обмена по нажатию кнопки "Copy"
