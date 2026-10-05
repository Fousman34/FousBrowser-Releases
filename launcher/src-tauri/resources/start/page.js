const clock = document.querySelector('time');
const date = document.querySelector('.date');
const search = document.querySelector('input');
function tick() {
  const now = new Date();
  clock.textContent = now.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
  clock.dateTime = now.toISOString();
  date.textContent = now.toLocaleDateString('ru-RU', { weekday: 'long', day: 'numeric', month: 'long' });
}
tick();
setInterval(tick, 10000);
document.addEventListener('keydown', (event) => {
  if (event.key === '/' && document.activeElement !== search && !event.ctrlKey && !event.metaKey && !event.altKey) {
    event.preventDefault();
    search.focus();
  }
});
document.querySelector('form').addEventListener('submit', (event) => {
  search.value = search.value.trim();
  if (!search.value) event.preventDefault();
});
