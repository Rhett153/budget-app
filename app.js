const dialog=document.querySelector('#planDialog');
const toast=document.querySelector('#toast');
const toastMessage=document.querySelector('#toastMessage');
let toastTimer;
function showToast(message){toastMessage.textContent=message;toast.classList.add('show');clearTimeout(toastTimer);toastTimer=setTimeout(()=>toast.classList.remove('show'),2800)}
document.querySelector('#generatePlan').addEventListener('click',()=>dialog.showModal());
document.querySelector('.dialog-done').addEventListener('click',()=>showToast('Your sample budget plan is ready to explore.'));
document.querySelector('#uploadStatement').addEventListener('click',()=>document.querySelector('#fileInput').click());
document.querySelector('#fileInput').addEventListener('change',event=>{const file=event.target.files?.[0];if(file)showToast(`${file.name} selected — uploads are disabled in this demo.`);event.target.value=''});
document.querySelector('#addAccount').addEventListener('click',()=>showToast('Bank connections are not enabled in this demo.'));
document.querySelectorAll('.download-button').forEach(button=>button.addEventListener('click',()=>showToast('Sample statements are for preview only.')));
document.querySelectorAll('.nav-link').forEach(link=>link.addEventListener('click',()=>{document.querySelectorAll('.nav-link').forEach(item=>item.classList.remove('active'));link.classList.add('active')}));
dialog.addEventListener('click',event=>{if(event.target===dialog)dialog.close()});
