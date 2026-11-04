# Site Cia de Teatro Poiesis — com painel de controle

## Como usar
1. Instale o Node.js 18+ (nodejs.org).
2. Nesta pasta: `node server.js`
3. Site: http://localhost:3000 · Painel: http://localhost:3000/#admin (ou link "Área restrita" no rodapé)

**Primeiro acesso:** usuário `admin`, senha `poiesis@2026`. O painel obriga você a escolher
seu usuário e uma nova senha (mín. 8 caracteres) antes de editar.
Opcional: defina `ADMIN_USER` e `ADMIN_PASS` antes de iniciar para já começar com seus dados.

## O que dá para editar
- **Peças Produzidas:** criar, excluir, nome, ano, versículo base (texto do rodapé da imagem),
  foto principal e 5 fotos do carrossel.
- **Espetáculo Atual:** criar, excluir, nome, descrição, versículo base, data(s), horário e duração.
- Clique em **Salvar alterações** para publicar. Excluir só vale após salvar.

## Onde ficam os dados
`data/` (textos e senha com hash) e `uploads/` (fotos). Faça backup dessas duas pastas.

## Hospedagem
Precisa de hospedagem que rode Node (Render, Railway, VPS…). Use HTTPS. Atrás de proxy, defina `TRUST_PROXY=1`.
Hospedagem só de arquivos estáticos não guarda alterações: nela o `index.html` abre em "modo de teste local"
(edições ficam só no navegador de quem editou).
