// main.cpp — веб-сервер, генерирующий интерфейс из XML
// Сборка:
//   g++ -std=c++17 main.cpp -o idhttpd -lpugixml -lboost_system -lssl -lcrypto -pthread

#include <boost/asio.hpp>
#include <pugixml.hpp>

#include <iostream>
#include <sstream>
#include <string>
#include <regex>
#include <memory>
#include <chrono>

namespace asio = boost::asio;
using tcp = asio::ip::tcp;

// ============================================================
// 1. Экранирование HTML (защита от XSS)
// ============================================================
std::string escape_html(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&':  out += "&amp;";  break;
            case '<':  out += "&lt;";   break;
            case '>':  out += "&gt;";   break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&#39;";  break;
            default:   out += c;
        }
    }
    return out;
}

// ============================================================
// 2. Генерация HTML из XML (белый список тегов)
// ============================================================
std::string generate_ui_from_xml(const std::string& xml_path) {
    pugi::xml_document doc;

    // parse_default НЕ разворачивает внешние сущности → защита от XXE
    pugi::xml_parse_result result = doc.load_file(
        xml_path.c_str(),
        pugi::parse_default | pugi::parse_trim_pcdata);

    if (!result) {
        std::cerr << "XML parse error: " << result.description() << "\n";
        return "<html><body>Ошибка загрузки интерфейса</body></html>";
    }

    pugi::xml_node root = doc.child("interface");
    if (!root) {
        return "<html><body>Корневой узел &lt;interface&gt; не найден</body></html>";
    }

    std::ostringstream html;
    html << "<!DOCTYPE html><html><head><meta charset='utf-8'>"
         << "<title>XML UI</title>"
         << "<style>"
            "body{font-family:sans-serif;margin:2em;background:#fafafa;}"
            "h1{color:#222;}p{color:#444;}"
            "button{padding:6px 12px;margin:4px;cursor:pointer;}"
            "input{padding:6px;margin:4px;display:block;}"
         "</style></head><body>";

    // Рекурсивный обход с белым списком разрешённых тегов
    for (pugi::xml_node node : root.children()) {
        std::string tag = node.name();

        if (tag == "heading") {
            html << "<h1>" << escape_html(node.text().get()) << "</h1>";
        }
        else if (tag == "paragraph") {
            html << "<p>" << escape_html(node.text().get()) << "</p>";
        }
        else if (tag == "button") {
            std::string id    = node.attribute("id").as_string();
            std::string label = node.attribute("label").as_string();
            html << "<button id='" << escape_html(id) << "'>"
                 << escape_html(label) << "</button>";
        }
        else if (tag == "input") {
            std::string name = node.attribute("name").as_string();
            std::string type = node.attribute("type").as_string("text");
            // Разрешаем только безопасные типы полей
            if (type != "text" && type != "password" && type != "email") {
                type = "text";
            }
            html << "<input type='" << escape_html(type)
                 << "' name='" << escape_html(name) << "'>";
        }
        // Любые другие теги молча игнорируются — защита от инъекций
    }

    html << "</body></html>";
    return html.str();
}

// ============================================================
// 3. HTTP-сессия
// ============================================================
class Session : public std::enable_shared_from_this<Session> {
public:
    explicit Session(tcp::socket socket)
        : socket_(std::move(socket)),
          timer_(socket_.get_executor()) {}

    void start() {
        do_read();
    }

private:
    // Защита от Slowloris: таймаут на всё соединение
    void reset_timeout(std::chrono::seconds sec = std::chrono::seconds(10)) {
        timer_.expires_after(sec);
        auto self = shared_from_this();
        timer_.async_wait([this, self](boost::system::error_code ec) {
            if (!ec) {
                // Таймаут истёк — принудительно закрываем соединение
                boost::system::error_code ignored;
                socket_.close(ignored);
            }
        });
    }

    void do_read() {
        reset_timeout();
        auto self = shared_from_this();

        // Читаем до первого заголовка; буфер ограничен 8 KB
        socket_.async_read_some(
            asio::buffer(buffer_, sizeof(buffer_)),
            [this, self](boost::system::error_code ec, std::size_t length) {
                if (ec) return;
                handle_request(length);
            });
    }

    void handle_request(std::size_t length) {
        std::string raw(buffer_, length);

        // Ограничение на размер запроса
        if (raw.size() > 8192) {
            send_response("HTTP/1.1 413 Payload Too Large\r\n"
                          "Connection: close\r\n\r\n");
            return;
        }

        // Разрешаем только GET
        if (raw.rfind("GET ", 0) != 0) {
            send_response("HTTP/1.1 405 Method Not Allowed\r\n"
                          "Allow: GET\r\nConnection: close\r\n\r\n");
            return;
        }

        // Извлекаем путь
        std::regex path_re("^GET (/[^ ]*) HTTP/1\\.[01]");
        std::smatch match;
        if (!std::regex_search(raw, match, path_re)) {
            send_response("HTTP/1.1 400 Bad Request\r\n"
                          "Connection: close\r\n\r\n");
            return;
        }
        std::string path = match[1];

        // Защита от path traversal
        if (path.find("..") != std::string::npos) {
            send_response("HTTP/1.1 403 Forbidden\r\n"
                          "Connection: close\r\n\r\n");
            return;
        }

        // Роутинг: только "/" и "/ui"
        if (path == "/" || path == "/ui") {
            std::string html = generate_ui_from_xml("interface.xml");

            std::ostringstream resp;
            resp << "HTTP/1.1 200 OK\r\n"
                 << "Content-Type: text/html; charset=utf-8\r\n"
                 << "Content-Length: " << html.size() << "\r\n"
                 // Security-заголовки
                 << "X-Content-Type-Options: nosniff\r\n"
                 << "X-Frame-Options: DENY\r\n"
                 << "Content-Security-Policy: default-src 'none'; "
                    "style-src 'unsafe-inline'\r\n"
                 << "Referrer-Policy: no-referrer\r\n"
                 << "Connection: close\r\n\r\n"
                 << html;
            send_response(resp.str());
        } else {
            send_response("HTTP/1.1 404 Not Found\r\n"
                          "Content-Length: 0\r\n"
                          "Connection: close\r\n\r\n");
        }
    }

    void send_response(const std::string& response) {
        auto self = shared_from_this();
        asio::async_write(
            socket_, asio::buffer(response),
            [this, self](boost::system::error_code ec, std::size_t) {
                if (ec) return;
                boost::system::error_code ignored;
                socket_.shutdown(tcp::socket::shutdown_send, ignored);
                socket_.close(ignored);
            });
    }

    tcp::socket socket_;
    asio::steady_timer timer_;
    char buffer_[8192];
};

// ============================================================
// 4. Сервер
// ============================================================
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

// ============================================================
// 5. main
// ============================================================
int main(int argc, char** argv) {
    unsigned short port = 8080;
    if (argc > 1) {
        try { port = static_cast<unsigned short>(std::stoi(argv[1])); }
        catch (...) { /* оставляем порт по умолчанию */ }
    }

    try {
        asio::io_context io;
        Server server(io, port);
        std::cout << "Сервер запущен на http://0.0.0.0:" << port << "\n";
        std::cout << "Откройте http://localhost:" << port << "/\n";
        io.run();
    } catch (std::exception& e) {
        std::cerr << "Fatal: " << e.what() << "\n";
        return 1;
    }
    return 0;
}