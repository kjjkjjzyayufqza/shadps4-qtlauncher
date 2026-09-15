// SPDX-FileCopyrightText: Copyright 2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <QString>
#include <utility>

namespace ShadNetRegister {

struct ServerAddress {
    QString host;
    quint16 port = 31313;
};

ServerAddress ParseServer(const QString& server);

bool IsValidNpid(const QString& npid);
bool IsValidEmail(const QString& email);

// Sends Create (command 2) to a running shadNet server.
// Returns {true, 0, ...} on success. error is the protocol ErrorType byte.
std::pair<bool, QString> CreateAccount(const QString& host, quint16 port, const QString& npid,
                                       const QString& password, const QString& email,
                                       const QString& secret_key = QString());

} // namespace ShadNetRegister
