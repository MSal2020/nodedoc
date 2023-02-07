

function generatePDF(){
    var date = document.getElementById("date-container").getAttribute("data-date");
    const element = document.getElementById("summaryreport");
    var clonedElement = element.cloneNode(true);
    $(clonedElement).css("display", "block");
    var opt = {
      margin:       1,
      filename:     "Summary Report " + date,
      image:        { type: 'jpeg', quality: 1 },
      html2canvas:  { scale: 2 },
      jsPDF:        { format: 'letter', orientation: 'portrait' }
    };
    html2pdf()
    .set(opt)
    .from(clonedElement)
    .save();
    clonedElement.remove();

}

function generatePDF2(){
    var date = document.getElementById("date-container").getAttribute("data-date");
    const element = document.getElementById("hide");
    var clonedElement = element.cloneNode(true);
    
    // change display of cloned element 
    $(clonedElement).css("display", "block");
    var opt = {
        margin:       1,
        filename:     "Medical Graphs " + date,
        image:        { type: 'jpeg', quality: 1 },
        html2canvas:  { scale: 2 },
        jsPDF:        { format: 'letter', orientation: 'portrait' }
      };
    html2pdf()
    .set(opt)
    .from(clonedElement)
    .save();
    clonedElement.remove();
}

function generatePDF3(){
  var date = document.getElementById("date-container").getAttribute("data-date");
  const element1 = document.getElementById("all");;
  const element2 = document.getElementById("hide");
  const element3 = document.getElementById("summaryreport");

  var clonedElement = element2.cloneNode(true);
  var clonedElement2 = element3.cloneNode(true);
  // change display of cloned element 
  $(clonedElement).css("display", "block");
  var pdfContent = clonedElement2.innerHTML + clonedElement.innerHTML;
  var opt = {
      margin:       1,
      filename:     "Medical Report " + date,
      image:        { type: 'jpeg', quality: 1 },
      html2canvas:  { scale: 2},
      jsPDF:        { format: 'letter', orientation: 'portrait' }
    };
  html2pdf()
  .set(opt)
  .from(pdfContent)
  .save();
  clonedElement.remove();
  clonedElement2.remove();
}
