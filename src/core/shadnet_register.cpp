// SPDX-FileCopyrightText: Copyright 2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "core/shadnet_register.h"

#include <cstring>

#include <QDeadlineTimer>
#include <QObject>
#include <QRegularExpression>
#include <QTcpSocket>
#include <QtEndian>

namespace ShadNetRegister {

namespace {

constexpr int kHeaderSize = 15;
constexpr quint8 kPacketRequest = 0;
constexpr quint8 kPacketReply = 1;
constexpr quint8 kPacketServerInfo = 3;
constexpr quint16 kCommandCreate = 2;
constexpr quint32 kProtocolVersion = 1;
constexpr int kTimeoutMs = 10000;
constexpr quint32 kMaxHandshakePayload = 4;
constexpr quint32 kMaxCreateReplyPayload = 16;

QByteArray EncodeVarint(quint32 value) {
    QByteArray out;
    while (true) {
        const char byte = static_cast<char>(value & 0x7F);
        value >>= 7;
        if (value != 0) {
            out.append(static_cast<char>(static_cast<unsigned char>(byte) | 0x80));
        } else {
            out.append(byte);
            return out;
        }
    }
}

QByteArray EncodeStringField(int field_number, const QString& value) {
    const QByteArray data = value.toUtf8();
    if (data.isEmpty()) {
        return {};
    }
    return EncodeVarint(static_cast<quint32>((field_number << 3) | 2)) +
           EncodeVarint(static_cast<quint32>(data.size())) + data;
}

QString ErrorMessage(quint8 error) {
    switch (error) {
    case 0:
        return QString();
    case 3:
        return QObject::tr("The NPID, password, or email is invalid.");
    case 10:
        return QObject::tr("The server rejected the registration.");
    case 11:
        return QObject::tr("That NPID is already registered.");
    case 12:
        return QObject::tr("That email provider is not allowed.");
    case 13:
        return QObject::tr("That email is already registered.");
    case 23:
        return QObject::tr("The server requires a registration key, or the key is wrong.");
    case 24:
        return QObject::tr("The server database rejected the registration.");
    default:
        return QObject::tr("Registration failed (error %1).").arg(error);
    }
}

int RemainingMs(const QDeadlineTimer& deadline) {
    if (deadline.hasExpired()) {
        return 0;
    }
    const qint64 remaining = deadline.remainingTime();
    if (remaining <= 0 || remaining > kTimeoutMs) {
        return 0;
    }
    return static_cast<int>(remaining);
}

bool RecvExact(QTcpSocket& sock, char* buf, int size, QDeadlineTimer deadline) {
    int got = 0;
    while (got < size) {
        const int remaining = RemainingMs(deadline);
        if (remaining <= 0) {
            return false;
        }
        if (sock.bytesAvailable() < 1 && !sock.waitForReadyRead(remaining)) {
            return false;
        }
        const qint64 n = sock.read(buf + got, size - got);
        if (n <= 0) {
            return false;
        }
        got += static_cast<int>(n);
    }
    return true;
}

bool RecvPacket(QTcpSocket& sock, quint8& type, quint16& command, quint64& packet_id,
                QByteArray& body, quint32 max_payload, QDeadlineTimer deadline) {
    char header[kHeaderSize];
    if (!RecvExact(sock, header, kHeaderSize, deadline)) {
        return false;
    }
    type = static_cast<quint8>(header[0]);
    command = qFromLittleEndian<quint16>(reinterpret_cast<const uchar*>(header + 1));
    const quint32 size = qFromLittleEndian<quint32>(reinterpret_cast<const uchar*>(header + 3));
    packet_id = qFromLittleEndian<quint64>(reinterpret_cast<const uchar*>(header + 7));
    if (size < static_cast<quint32>(kHeaderSize) ||
        size - static_cast<quint32>(kHeaderSize) > max_payload) {
        return false;
    }
    const int payload = static_cast<int>(size - kHeaderSize);
    body.resize(payload);
    if (payload > 0 && !RecvExact(sock, body.data(), payload, deadline)) {
        return false;
    }
    return true;
}

} // namespace

ServerAddress ParseServer(const QString& server) {
    ServerAddress out;
    const QString trimmed = server.trimmed();
    const int colon = trimmed.lastIndexOf(QLatin1Char(':'));
    if (colon > 0) {
        out.host = trimmed.left(colon);
        bool ok = false;
        const int port = trimmed.mid(colon + 1).toInt(&ok);
        if (ok && port > 0 && port <= 65535) {
            out.port = static_cast<quint16>(port);
        }
    } else {
        out.host = trimmed;
    }
    return out;
}

bool IsValidNpid(const QString& npid) {
    static const QRegularExpression re(
        QRegularExpression::anchoredPattern(QStringLiteral("[A-Za-z][A-Za-z0-9_-]{2,15}")));
    return re.match(npid).hasMatch();
}

bool IsValidEmail(const QString& email) {
    const QString trimmed = email.trimmed();
    const int at = trimmed.indexOf(QLatin1Char('@'));
    return at > 0 && at < trimmed.size() - 1 && !trimmed.contains(QLatin1Char(' '));
}

std::pair<bool, QString> CreateAccount(const QString& host, quint16 port, const QString& npid,
                                       const QString& password, const QString& email,
                                       const QString& secret_key) {
    if (host.trimmed().isEmpty()) {
        return {false, QObject::tr("No shadNet server is configured in Settings.")};
    }
    if (!IsValidNpid(npid)) {
        return {false, QObject::tr("NPID must be 3-16 characters, start with a letter, and use "
                                   "only letters, numbers, '-' or '_'.")};
    }
    if (password.isEmpty()) {
        return {false, QObject::tr("Password cannot be empty.")};
    }
    if (!IsValidEmail(email)) {
        return {false, QObject::tr("Enter a valid email address.")};
    }

    QByteArray message = EncodeStringField(1, npid) + EncodeStringField(2, password) +
                         EncodeStringField(4, email) + EncodeStringField(5, secret_key);
    QByteArray proto_blob;
    const quint32 msg_size = static_cast<quint32>(message.size());
    proto_blob.resize(4);
    qToLittleEndian(msg_size, reinterpret_cast<uchar*>(proto_blob.data()));
    proto_blob += message;

    QByteArray request(kHeaderSize + proto_blob.size(), 0);
    request[0] = static_cast<char>(kPacketRequest);
    qToLittleEndian(kCommandCreate, reinterpret_cast<uchar*>(request.data() + 1));
    qToLittleEndian(static_cast<quint32>(request.size()),
                    reinterpret_cast<uchar*>(request.data() + 3));
    qToLittleEndian(static_cast<quint64>(1), reinterpret_cast<uchar*>(request.data() + 7));
    memcpy(request.data() + kHeaderSize, proto_blob.constData(), proto_blob.size());

    const QDeadlineTimer deadline(kTimeoutMs);
    QTcpSocket sock;
    sock.connectToHost(host.trimmed(), port);
    if (!sock.waitForConnected(RemainingMs(deadline))) {
        sock.abort();
        return {false, QObject::tr("Could not connect to %1:%2 (%3)")
                           .arg(host)
                           .arg(port)
                           .arg(sock.errorString())};
    }

    quint8 type = 0;
    quint16 command = 0;
    quint64 packet_id = 0;
    QByteArray body;
    if (!RecvPacket(sock, type, command, packet_id, body, kMaxHandshakePayload, deadline) ||
        type != kPacketServerInfo || body.size() < 4) {
        sock.abort();
        return {false, QObject::tr("The server did not send a valid handshake.")};
    }
    const quint32 version = qFromLittleEndian<quint32>(reinterpret_cast<const uchar*>(body.data()));
    if (version != kProtocolVersion) {
        sock.abort();
        return {false, QObject::tr("Protocol version mismatch (server v%1, launcher v%2).")
                           .arg(version)
                           .arg(kProtocolVersion)};
    }

    sock.write(request);
    if (!sock.waitForBytesWritten(RemainingMs(deadline))) {
        sock.abort();
        return {false, QObject::tr("Failed to send the registration request.")};
    }
    if (!RecvPacket(sock, type, command, packet_id, body, kMaxCreateReplyPayload, deadline) ||
        type != kPacketReply || command != kCommandCreate || packet_id != 1 || body.isEmpty()) {
        sock.abort();
        return {false, QObject::tr("Unexpected reply from the server.")};
    }

    const quint8 error = static_cast<quint8>(body[0]);
    if (error != 0) {
        return {false, ErrorMessage(error)};
    }
    return {true, QObject::tr("Account created.")};
}

} // namespace ShadNetRegister
