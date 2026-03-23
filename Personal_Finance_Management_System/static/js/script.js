function disableButton(optbtn,femail,otp,reset)
{
    var email_val = document.getElementById(femail.id).value;
    if (email_val.length > 10){
        optbtn.disabled = true;
        document.getElementById(femail.id).disabled = true;
        document.getElementById(otp.id).disabled = false;
        document.getElementById(reset.id).disabled = false;
    }
}


var trace1 = {
  type: 'bar',
  x: [1, 2, 3, 4],
  y: [5, 10, 2, 8],
  marker: {
      color: '#C8A2C8',
      line: {
          width: 2.5
      }
  }
};

var data = [ trace1 ];

var layout = {
  title: 'Responsive to window\'s size!',
  font: {size: 18}
};

var config = {responsive: true}

Plotly.newPlot('myDiv', data, layout, config );



$(document).ready(function(){
    $(".multi_select").selectpicker();
})
