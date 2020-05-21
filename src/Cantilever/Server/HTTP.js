import http from "http";

export function startHttpServerRaw(config) {
  return function() {
    const server = http.createServer((req, res) => {
      const chunks = [];
      req.on("data", chunk => chunks.push(chunk));
      req.on("end", () => {
        const bodyBuffer = Buffer.concat(chunks);
        const headersList = [];
        for (const [k, v] of Object.entries(req.headers)) {
          if (typeof v === "string") {
            headersList.push({ key: k, value: v });
          } else if (Array.isArray(v)) {
            headersList.push({ key: k, value: v.join(", ") });
          }
        }

        const requestData = {
          method: req.method || "GET",
          url: req.url || "/",
          headers: headersList,
          bodyText: bodyBuffer.toString("utf8"),
          bodyBytes: Array.from(bodyBuffer)
        };

        const respondFn = function(response) {
          return function() {
            res.statusCode = response.statusCode;
            for (const h of (response.headers || [])) {
              res.setHeader(h.key, h.value);
            }
            if (response.bodyBytes && response.bodyBytes.length > 0) {
              res.end(Buffer.from(response.bodyBytes));
            } else if (response.bodyText) {
              res.end(response.bodyText);
            } else {
              res.end();
            }
          };
        };

        config.handler(requestData)(respondFn)();
      });
    });

    server.listen(config.port, config.host, () => {
      console.log(`[Cantilever PKI Server] listening on http://${config.host}:${config.port}`);
    });

    return function() {
      server.close();
    };
  };
}
