# Интеграция с iOS

Архив содержит срез iOS-исходников без полного Xcode-проекта. Готовая проверенная
на iPhone сборка здесь не заявляется. В Linux проверены C API и клиентская
библиотека без Go, агента и libcurl; ветка Apple Security, Swift и XCFramework
требуют сборки и проверки на macOS.

## Библиотека

Нужен Xcode и OpenSSL 3, собранный для device arm64 и simulator arm64/x86_64.
Переменные указывают на префиксы с `include/openssl`, `lib/libssl.a`,
`lib/libcrypto.a`; библиотека симулятора должна содержать обе архитектуры.

```sh
OPENSSL_IOS_DEVICE=/path/to/openssl/iphoneos \
OPENSSL_IOS_SIMULATOR=/path/to/openssl/iphonesimulator \
sh sparta/ios/build-xcframework.sh
```

Скрипт собирает `sparta/build/ios/SpartaC.xcframework`. Он не скачивает
зависимости. Подключите framework к target расширения и добавьте
`SpartaCore.swift`. Модуль C называется `SpartaC`.
Учтите возможные конфликты, если приложение уже статически включает другую
версию OpenSSL: используйте согласованную сборку зависимостей.

На Apple без явного CA-файла цепочка проверяется через `SecTrust` с SSL-политикой
для имени узла. При явно заданном CA-файле используется проверка OpenSSL с этим
CA. Проверки имени и сертификата не отключаются. Браузерные TLS-отпечатки uTLS
не реализованы.

## PacketTunnelProvider

Оставьте существующие NetworkExtension, Keychain, настройки маршрутов и mapdns,
а также hev-socks5-tunnel 2.19.1. hev уже написан на C; утун и его владение
остаются у `NEPacketTunnelProvider`.

Вместо `LocalPort.pick()` и `GostcoreStart(...)`:

```swift
let socksPort = try SpartaCore.start(
    profile: config.profile,
    password: password,
    nodeAddress: nodeAddr,
    port: 0,
    user: credentials.user,
    socksPassword: credentials.pass
)
// Передать именно возвращённый socksPort в HevConfig.render(...).
```

Порт резервируется самим C-слушателем и не освобождается между выбором порта
и запуском сервиса. Имя из профиля сохраняется для SNI/Host/проверки сертификата;
`nodeAddress` — заранее разрешённый числовой IP:порт для подключения вне VPN.

Проверка связи: `try SpartaCore.check()`. Остановка: `SpartaCore.stop()`.
Остановка закрывает активные сеансы; параллельная проверка связи отменяется.
Продолжайте вызывать `hev_socks5_tunnel_quit()` и ждать завершения потока hev
до освобождения его конфигурации и дескриптора utun. Обёртка C не владеет utun.
Если hev не завершился в срок, нельзя считать его остановленным и повторно
использовать относящиеся к нему ресурсы.

Одноразовые SOCKS-креды нужны и в hev, и в `SpartaCore.start`; они не должны
попадать в журналы. Keychain и App Group не переносятся в обычный C-код:
это системная интеграция существующего приложения.

## Что проверить на устройстве

После сборки проверить Safari/Telegram, UDP, отсутствие прямого обхода при
недоступном узле, остановку/повторный запуск и `phys_footprint` под нагрузкой.
По умолчанию допускается 96 локальных TCP-клиентов; ограничение 50 МиБ на
устройстве не подтверждено измерением. Это требуется проверить до замены
действующего Network Extension.
