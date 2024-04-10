const search = document.querySelector('.monitor_slaves_search input'),
    table_rows = document.querySelectorAll('tbody tr'),
    table_headings = document.querySelectorAll('thead th');

// 1. Searching for specific data of HTML table
search.addEventListener('input', function searchTable(e) {
    var input = this.value;
    var array = input.split(",");
    for (let index = 0; index < array.length; index++) {
        const element = array[index];
        table_rows.forEach((row, i) => {
            let table_data = row.textContent.toLowerCase(),
                search_data = search.value.toLowerCase();
    
            row.classList.toggle('hide', table_data.indexOf(search_data) < 0);
            row.style.setProperty('--delay', i / 25 + 's');
        })   
    }
    document.querySelectorAll('tbody tr:not(.hide)').forEach((visible_row, i) => {
        visible_row.style.backgroundColor = (i % 2 == 0) ? 'transparent' : '#0000000b';
    });
});

/*document
  .querySelector(".monitor_slaves_search input")
  .addEventListener("keypress", function (e) {
    if (e.key === "Enter") {
      var input = this.value;
      var array = input.split(",");
      for (let index = 0; index < array.length; index++) {
        const element = array[index];
        if (element.includes(":")){
            var parts = element.split(":")
            
        }
      }
      console.log(result);
      alert(result);
    }
  });*/
