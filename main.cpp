#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <pugixml.hpp>
#include <string>
#include <sstream>
#include <unordered_map>
#include <regex>

namespace asio = boost::asio;
using tcp = asio::ip::tcp;

// ---------- Генерация HTML из XML (безопасная) ----------
std::string generate_ui_from_xml(const std::string& xml_path) {
    pugi::xml_document doc;
    // ВАЖНО: parse_default НЕ разворачивает внешние сущности → защита от XXE
    pugi::xml_parse_result result = doc.load_file(xml_path.c_str(),
        pugi::parse_default | pugi::parse_trim_pcdata);

    if (!result) {
        return "<html><body>Ошибка загрузки интерфейса</body></html>";
    }

    std::ostringstream html;
    html << "<!DOCTYPE html><html><head><meta charset='utf-8'>";
    html << "<style>body{font-family:sans-serif;margin:2em;}</style></head><body>";

    // Рекурсивный обход узлов с жёсткой проверкой допустимых тегов
    // (белый список — критически важно!)
    for (pugi::xml_node node : doc.child("interface").children()) {
        std::string tag = node.name();

        // Белый список разрешённых элементов интерфейса
        if (tag == "heading") {
            html << "<h1>" << escape_html(node.text().get()) << "</h1>";
        } else if (tag == "paragraph") {
            html << "<p>" << escape_html(node.text().get()) << "</p>";
        } else if (tag == "button") {
            std::string id = node.attribute("id").as_string();
            std::string label = node.attribute("label").as_string();
            // Экранируем всё, что попадает в HTML
            html << "<button id='" << escape_html(id) << "'>"
                 << escape_html(label) << "</button>";
        } else if (tag == "input") {
            std::string name = node.attribute("name").as_string();
            std::string type = node.attribute("type").as_string("text");
            // Проверка типа: разрешаем только безопасные
            if (type != "text" && type != "password" && type != "email") {
                type = "text";
            }
            html << "<input type='" << escape_html(type)
                 << "' name='" << escape_html(name) << "'>";
        }
        // Любые другие теги игнорируются — это защита от инъекций
    }

    html << "</body></html>";
    return html.str();
}

// Экранирование HTML-спецсимволов (защита от XSS)
std::string escape_html(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default: out += c;
        }
    }
    return out;
}

// ---------- HTTP-сессия с защитой ----------
class Session : public std::enable_shared_from_this<Session> {
public:
    Session(tcp::socket socket) : socket_(std::move(socket)) {}

    void start() { do_read(); }

private:
    void do_read() {
        auto self = shared_from_this();
        // Ограничение размера запроса — защита от переполнения буфера
        socket_.async_read_some(asio::buffer(buffer_, sizeof(buffer_)),
            [this, self](boost::system::error_code ec, std::size_t length) {
                if (!ec) {
                    handle_request(length);
                }
            });
    }

    void handle_request(std::size_t length) {
        std::string raw(buffer_, length);

        // Проверка: запрос не должен быть слишком длинным
        if (raw.size() > 8192) {  // 8KB лимит для заголовков
            send_response("HTTP/1.1 413 Payload Too Large\r\n\r\n");
            return;
        }

        // Проверка метода: разрешаем только GET (для примера)
        if (raw.find("GET ") != 0) {
            send_response("HTTP/1.1 405 Method Not Allowed\r\n\r\n");
            return;
        }

        // Извлечение пути с проверкой на path traversal
        std::regex path_re("^GET (/[^ ]*) HTTP/1\\.[01]");
        std::smatch match;
        if (!std::regex_search(raw, match, path_re)) {
            send_response("HTTP/1.1 400 Bad Request\r\n\r\n");
            return;
        }
        std::string path = match[1];

        // Блокируем попытки выхода за пределы каталога
        if (path.find("..") != std::string::npos) {
            send_response("HTTP/1.1 403 Forbidden\r\n\r\n");
            return;
        }

        // Только один разрешённый маршрут — отдаём интерфейс из XML
        if (path == "/" || path == "/ui") {
            std::string html = generate_ui_from_xml("interface.xml");

            // Security-заголовки (критически важно!)
            std::ostringstream resp;
            resp << "HTTP/1.1 200 OK\r\n"
                 << "Content-Type: text/html; charset=utf-8\r\n"
                 << "Content-Length: " << html.size() << "\r\n"
                 << "X-Content-Type-Options: nosniff\r\n"
                 << "X-Frame-Options: DENY\r\n"
                 << "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'\r\n"
                 << "Referrer-Policy: no-referrer\r\n"
                 << "Connection: close\r\n\r\n"
                 << html;
            send_response(resp.str());
        } else {
            send_response("HTTP/1.1 404 Not Found\r\n\r\n");
        }
    }

    void send_response(const std::string& response) {
        auto self = shared_from_this();
        asio::async_write(socket_, asio::buffer(response),
            [this, self](boost::system::error_code, std::size_t) {
                // Закрываем соединение после ответа (упрощение)
            });
    }

    tcp::socket socket_;
    char buffer_[8192];
};

// ---------- Сервер ----------
class Server {
public:
    Server(asio::io_context& io, unsigned short port)
        : acceptor_(io, tcp::endpoint(tcp::v4(), port)) {
        do_accept();
    }

private:
    void do_accept() {
        acceptor_.async_accept(
            [this](boost::system::error_code ec, tcp::socket socket) {
                if (!ec) {
                    std::make_shared<Session>(std::move(socket))->start();
                }
                do_accept();
            });
    }

    tcp::acceptor acceptor_;
};

int main() {
    try {
        asio::io_context io;
        Server server(io, 8443);  // В реальности — TLS-порт
        io.run();
    } catch (std::exception& e) {
        // Логирование, но не раскрытие деталей клиенту
    }
    return 0;
}