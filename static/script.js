async function main() {
    var res = await fetch('/time.json');
    var {0: j} = await res.json();

    document.querySelector('svg text').textContent = j;

    var svg = document.querySelector('svg');
    var date = new Date(Date.parse(j));

    svg.style.setProperty('--start-seconds', date.getSeconds());
    svg.style.setProperty('--start-minutes', date.getMinutes());
    svg.style.setProperty('--start-hours', date.getHours() % 12);
}

main();

setInterval(main, 5000);

