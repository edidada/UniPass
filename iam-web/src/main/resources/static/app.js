'use strict';
const status = document.getElementById('status');
const result = document.getElementById('result');
async function read(path) {
  const response = await fetch(path, {credentials: 'same-origin', redirect: 'error'});
  if (!response.ok) throw new Error(response.status === 401 ? '请重新登录。' : '服务暂时不可用，请稍后重试。');
  return response.json();
}
read('/bff/profile').then(profile => { status.textContent = '已登录：' + profile.application; }).catch(error => { status.textContent = error.message; });
document.getElementById('data').addEventListener('click', async () => {
  try { result.textContent = JSON.stringify(await read('/bff/data'), null, 2); } catch (error) { result.textContent = error.message; }
});
document.getElementById('logout').addEventListener('click', async () => {
  try {
    const csrf = await read('/csrf');
    const form = document.createElement('form'); form.method = 'POST'; form.action = '/logout';
    const input = document.createElement('input'); input.type = 'hidden'; input.name = '_csrf'; input.value = csrf.token;
    form.append(input); document.body.append(form); form.submit();
  } catch (error) { status.textContent = error.message; }
});
