#include <QApplication>
#include <QIcon>
#include <QDir>
#include <QProcess>
#include <QUuid>
#include <QSettings>
#include <QDesktopWidget>
#include <QStandardPaths>
#include <QDebug>

#include "ui_klogin.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <shadow.h>
#include <pwd.h>
#include <grp.h>
#include <crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <paths.h>

class KLogin : public QMainWindow {
    Q_OBJECT

    public:
        KLogin(QWidget *parent = Q_NULLPTR, Qt::WindowFlags flags = Qt::Window);
        ~KLogin();

        void loginProcess(const QByteArray username, const QByteArray session);

    public Q_SLOTS:
        void slotLogin();
        void slotShutdown();
        void slotReboot();

    private:
        void fitOnScreen();

        Ui_KLoginWindow ui;
};

KLogin::KLogin(QWidget *parent, Qt::WindowFlags flags)
    :  QMainWindow(parent, flags) {
    ui.setupUi(this);

    setWindowFlags(Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint);

    fitOnScreen();

    connect(ui.loginButton, SIGNAL(clicked()), this, SLOT(slotLogin()));

    connect(ui.actionShutdown, SIGNAL(triggered()),
        this, SLOT(slotShutdown()));
    connect(ui.actionReboot, SIGNAL(triggered()),
        this, SLOT(slotReboot()));

    ::setsid();
    ::chdir("/");

    ::setpwent();
    while (true) {
        struct passwd* pw = ::getpwent();
        if (!pw) {
            break;
        }

        // skip system users (>999)
        if (pw->pw_uid == 0 || pw->pw_uid > 999) {
            ui.userNameBox->addItem(pw->pw_name);
        }
    }
    ::endpwent();

    QDir dir("/usr/share/xsessions");
    foreach (const QString &entry, dir.entryList(QDir::Files)) {
        if (entry.endsWith(".desktop")) {
            QSettings desktopsettings("/usr/share/xsessions/" + entry, QSettings::IniFormat);
            const QString sessionname = desktopsettings.value("Desktop Entry/Name").toString();
            const QString sessionexec = desktopsettings.value("Desktop Entry/Exec").toString();
            if (!sessionname.isEmpty() && !sessionexec.isEmpty()) {
                const QString sessionicon = desktopsettings.value("Desktop Entry/Icon").toString();
                ui.sessionBox->addItem(QIcon::fromTheme(sessionicon), sessionname, sessionexec);
            }
        }
    }
    if (ui.sessionBox->count() < 1) {
        ui.loginButton->setEnabled(false);
    }
}

KLogin::~KLogin() {
}

void KLogin::slotLogin() {
    QFile nologin("/etc/nologin");
    if (nologin.exists()) {
        qDebug() << "reading /etc/nologin";

        QByteArray reason;
        if (nologin.open(QFile::ReadOnly)) {
            reason = nologin.readAll();
        }
        qCritical() << "login is not permited at the moment\n" << reason;
        ui.userNameBox->setFocus();
        ui.passwordEdit->clear();
        return;
    }

    const QByteArray username = ui.userNameBox->currentText().toUtf8();
    const QByteArray password = ui.passwordEdit->text().toUtf8();

    // FIXME: /etc/usertty support, http://linux.die.net/man/1/login
    QFile securetty("/etc/securetty");
    if (username == "root" && securetty.exists()) {
        const QByteArray ttyout = ::ttyname(STDIN_FILENO);
        const QByteArray ttybase = QFileInfo(ttyout).fileName().toUtf8();

        qDebug() << "reading /etc/securetty";

        if (!securetty.open(QFile::ReadOnly)) {
            qCritical() << "could not read /etc/securetty";
            ui.userNameBox->setFocus();
            ui.passwordEdit->clear();
            return;
        }
        while (true) {
            if (securetty.readLine().trimmed() == ttybase) {
                break;
            }

            if (securetty.atEnd()) {
                qCritical() << "current tty is not secure" << ttyout;
                ui.userNameBox->setFocus();
                ui.passwordEdit->clear();
                return;
            }
        }
    }

    struct passwd* pw = ::getpwnam(username);
    if (!pw) {
        qCritical() << "null passwd struct";
        ui.userNameBox->setFocus();
        ui.passwordEdit->clear();
        return;
    }

    // TODO: check if shell is in /etc/shells?

    QByteArray pw_passwd = pw->pw_passwd;
    if (pw_passwd == "x" || pw_passwd == "*") {
        if (::lckpwdf() == 0) {
            ::setspent();

            bool goback = false;
            struct spwd *spw = ::getspnam(username);
            if (spw) {
                pw_passwd = spw->sp_pwdp;

                const long int pw_max = spw->sp_max;
                const long int pw_inact = spw->sp_inact;
                const long int pw_expire = spw->sp_expire;

                const time_t current = ::time(Q_NULLPTR) / 86400L;
                if (pw_max != -1 && pw_max < current) {
                    qCritical() << "you must change your password" << current << pw_max;
                    goback = true;
                }

                if (!goback && pw_inact != -1 && pw_inact < current) {
                    qCritical() << "your account is inactive" << current << pw_inact;
                    goback = true;
                }

                if (!goback && pw_expire != -1 && pw_expire < current) {
                    qCritical() << "your account has expired" << current << pw_expire;
                    goback = true;
                }

            } else {
                qCritical() << "null shadow passwd struct";
                goback = true;
            }

            ::endspent();
            ::ulckpwdf();

            if (goback) {
                ui.userNameBox->setFocus();
                ui.passwordEdit->clear();
                return;
            }
        } else {
            qCritical() << "could not lock for shadow passwd struct";
            ui.userNameBox->setFocus();
            ui.passwordEdit->clear();
            return;
        }
    }

    const int sessionindex = ui.sessionBox->currentIndex();
    QByteArray session = ui.sessionBox->itemData(sessionindex).toByteArray();

    if (!QFile::exists(session)) {
        session = QStandardPaths::findExecutable(session).toUtf8();
    }
    if (session.isEmpty()) {
        qCritical() << "session does not exists and is not in path either" << session;
        return;
    }

    if (pw_passwd.isEmpty() || ::crypt(password, pw_passwd) == pw_passwd) {
        hide();

        const pid_t pid = ::fork();
        if (pid != -1) {
            if (pid == 0) {
                loginProcess(username, session);
            } else {
                int status;
                const pid_t unused = ::waitpid(pid, &status, 0);
                Q_UNUSED(unused);
                if (status != 0) {
                    fitOnScreen();
                    qCritical() << "login failed";
                }
            };
        } else {
            fitOnScreen();
            qCritical() << "could not fork";
        }

        fitOnScreen();
    } else {
        qCritical() << "incorrect password";
    }

    ui.passwordEdit->setFocus();
    ui.passwordEdit->clear();
}

void KLogin::loginProcess(const QByteArray username, const QByteArray session) {
    qDebug() << "logging as" << username;

    struct passwd* pw = ::getpwnam(username);
    if (!pw) {
        qCritical() << "null passwd struct";
        return;
    }

    const uid_t pw_uid = pw->pw_uid;
    const gid_t pw_gid = pw->pw_gid;
    QByteArray pw_dir = pw->pw_dir;
    const QByteArray pw_shell = pw->pw_shell;
    const QByteArray pw_xauth = pw_dir + "/.Xauthority";
    const QByteArray pw_display = qgetenv("DISPLAY");
    QByteArray pw_path = "/usr/local/bin:/bin:/usr/bin";

    if (pw_display.isEmpty()) {
        qCritical() << "DISPLAY is empty";
        return;
    }

    if (pw_uid == 0) {
        pw_path = "/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin";
    }

    if (!QDir(pw_dir).exists()) {
        qWarning() << "using fallback home dir instead of" << pw_dir;
        pw_dir = "/";
    }

    const QStringList xhost_args = QStringList() << "+si:localuser:" + username;
    if (QProcess::execute("xhost", xhost_args) != 0) {
        qWarning() << "xhost error";
    }

    if (::getgid() != pw_gid && ::getuid() != pw_uid) {
        if (::setgid(pw_gid) != 0) {
            qCritical() << "setgid error" << ::strerror(errno);
            return;
        }

        if (::initgroups(username, pw_gid) != 0) {
            qCritical() << "initgroups error" << ::strerror(errno);
            return;
        }

        if (::setuid(pw_uid) != 0) {
            qCritical() << "setuid error" << ::strerror(errno);
            return;
        }

        ::unsetenv("DBUS_SESSION_BUS_ADDRESS");
    }

    if (::chdir(pw_dir) != 0) {
        qCritical() << "chdir error" << ::strerror(errno);
        return;
    }

    qputenv("USER", username);
    qputenv("LOGNAME", username);
    qputenv("HOME", pw_dir);
    qputenv("PWD", pw_dir);
    qputenv("SHELL", pw_shell);
    qputenv("PATH", pw_path);
    qputenv("XAUTHORITY", pw_xauth);
    qputenv("MAIL", _PATH_MAILDIR);

    if (!QFile::exists(pw_xauth)) {
        char buffer[HOST_NAME_MAX];
        if (::gethostname(buffer, sizeof(buffer)) != 0) {
            qWarning() << "gethostname" << ::strerror(errno);
        }
        const QString pw_hostname = QString::fromLatin1(buffer);
        const QByteArray pw_randomkey = QUuid::createUuid().toByteArray();
        const QStringList xauth_args = QStringList() << "add"
            << pw_hostname + pw_display << "." << pw_randomkey;
        if (QProcess::execute("xauth", xauth_args) != 0) {
            qWarning() << "xauth error";
        }
    }

    // TODO: utmp?

    qDebug() << "executing" << session;
    const int status = ::execl(session.constData(), session.constData(), Q_NULLPTR);
    if (status != 0) {
        qCritical() << "execl error" << ::strerror(errno);
    }

    qDebug() << "exiting with status" << status;
    ::exit(status);
}

void KLogin::slotShutdown() {
    qDebug() << "shutting down";

    if (QProcess::execute("poweroff") != 0) {
        qCritical() << "could not poweroff";
    } else {
        qApp->exit(0);
    }
}

void KLogin::slotReboot() {
    qDebug() << "rebooting";

    if (QProcess::execute("reboot") != 0) {
        qCritical() << "could not reboot";
    } else {
        qApp->exit(0);
    }
}

void KLogin::fitOnScreen() {
    setGeometry(qApp->desktop()->screenGeometry(this));
    updateGeometry();
    showMaximized();
}

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);

    app.setApplicationName("klogin");

    KLogin login;

    return app.exec();
}

#include "klogin.moc"
