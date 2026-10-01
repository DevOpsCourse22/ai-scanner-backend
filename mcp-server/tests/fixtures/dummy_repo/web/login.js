// Login page helpers with a planted DOM XSS sink.

function showGreeting(name) {
  // planted: innerHTML assignment with untrusted input (XSS risk)
  document.getElementById("greet").innerHTML = "Hi " + name;
}

module.exports = { showGreeting };
