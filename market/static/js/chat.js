/* Chat client for global chat and 1:1 DMs.
 *
 * XSS-safety: all message data received from the server is inserted with
 * textContent / createTextNode — never innerHTML — so message content is
 * always rendered as plain text.
 */
(function () {
  "use strict";

  var box = document.getElementById("chat-box");
  if (!box) return;

  var room = box.dataset.room;
  var myId = parseInt(box.dataset.me, 10);
  var form = document.getElementById("chat-form");
  var input = document.getElementById("chat-input");
  var errorEl = document.getElementById("chat-error");

  var socket = io();

  socket.on("connect", function () {
    socket.emit("join", { room: room });
  });

  socket.on("new_message", function (msg) {
    appendMessage(msg);
    box.scrollTop = box.scrollHeight;
  });

  socket.on("error_message", function (data) {
    errorEl.textContent = data && data.error ? data.error : "오류가 발생했습니다.";
    setTimeout(function () { errorEl.textContent = ""; }, 3000);
  });

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    var content = input.value.trim();
    if (!content) return;
    if (content.length > 500) {
      errorEl.textContent = "메시지는 500자 이하여야 합니다.";
      return;
    }
    socket.emit("send_message", { room: room, content: content });
    input.value = "";
    input.focus();
  });

  function appendMessage(msg) {
    var wrap = document.createElement("div");
    wrap.className = "chat-msg" + (msg.sender_id === myId ? " mine" : "");

    var sender = document.createElement("span");
    sender.className = "chat-sender";
    sender.textContent = msg.sender;

    var content = document.createElement("span");
    content.className = "chat-content";
    content.textContent = msg.content;

    var time = document.createElement("span");
    time.className = "chat-time";
    time.textContent = msg.time;

    wrap.appendChild(sender);
    wrap.appendChild(content);
    wrap.appendChild(time);
    box.appendChild(wrap);
  }

  box.scrollTop = box.scrollHeight;
})();
