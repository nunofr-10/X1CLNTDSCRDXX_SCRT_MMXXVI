<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Dashboard · Plantillas de Embeds de Twitch (Admin)</title>
<link rel="icon" type="image/svg+xml" href="{{ url_for('static', filename='favicon.svg') }}">
<script src="https://cdn.tailwindcss.com"></script>
<script>
  tailwind.config = {
    theme: {
      extend: {
        colors: {
          base: "#07080c",
          panel: "#171a23",
          card: "#12141c",
          border: "#252836",
          accent: "#5865f2",
          muted: "#8b8fa3",
          ok: "#23a55a",
          err: "#ed4245",
        },
      },
    },
  };
</script>
<style>
  body { font-family: "Segoe UI", Roboto, -apple-system, sans-serif; }

  .var-chip {
    cursor: pointer;
    transition: border-color 0.15s ease, background 0.15s ease;
  }
  .var-chip:hover { border-color: #5865f2; background: rgba(88,101,242,0.1); }

  .discord-preview {
    background: #2b2d31;
    border-left: 4px solid var(--preview-color, #5865f2);
    border-radius: 4px;
    padding: 10px 14px;
    font-size: 13px;
    color: #dbdee1;
    white-space: pre-wrap;
    word-break: break-word;
  }
  .discord-preview .preview-title {
    color: #fff;
    font-weight: 700;
    margin-bottom: 6px;
  }
  .discord-preview .preview-footer {
    color: #949ba4;
    font-size: 11px;
    margin-top: 8px;
  }
</style>
</head>
<body class="bg-base text-slate-100 min-h-screen">

{% include "_simulation_banner.html" %}

{% macro vars_panel(panel_id, vars) %}
  <div class="border border-border rounded-lg">
    <button type="button" class="vars-toggle-btn w-full flex items-center justify-between px-4 py-3 text-xs font-bold uppercase text-muted hover:text-slate-100"
            data-panel="{{ panel_id }}">
      <span>🧩 Variables disponibles</span>
      <span class="caret">▾</span>
    </button>
    <div id="{{ panel_id }}" class="hidden px-4 pb-4 flex flex-wrap gap-2">
      {% for v in vars %}
        <span class="var-chip text-xs font-mono bg-panel border border-border rounded-full px-3 py-1.5"
              data-token="{{ v.token }}" title="{{ v.label }}">
          {{ v.token }} <span class="text-muted">· {{ v.label }}</span>
        </span>
      {% endfor %}
    </div>
    <p class="px-4 pb-3 text-xs text-muted">Haz clic en una variable para insertarla en el último campo (título, descripción o footer) que hayas tocado.</p>
  </div>
{% endmacro %}

  <header class="flex items-center justify-between px-8 py-5 border-b border-border">
    <div class="flex items-center gap-3 text-sm">
      <a href="{{ url_for('admin_panel') }}" class="text-muted hover:text-slate-100">← Panel de Administración</a>
      <span class="text-border">|</span>
      <h1 class="text-xl font-bold text-white">🚨 Embeds de Logs de Twitch</h1>
    </div>
    {% if user %}
      <div class="text-sm text-muted">
        Conectado como <span class="text-slate-200 font-medium">{{ user.username }}</span>
      </div>
    {% endif %}
  </header>

  <main class="px-6 py-8 max-w-5xl mx-auto space-y-6">

    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for category, message in messages %}
          <div class="rounded-lg px-4 py-3 text-sm border
            {% if category == 'success' %} bg-ok/10 border-ok text-ok
            {% else %} bg-err/10 border-err text-err {% endif %}">
            {{ message }}
          </div>
        {% endfor %}
      {% endif %}
    {% endwith %}

    <div class="rounded-lg px-4 py-3 text-sm border bg-accent/10 border-accent/40 text-slate-200">
      Estas plantillas definen el aspecto de los avisos de sanciones de Twitch para
      <strong>todos los clientes</strong> por igual. Ningún cliente puede editarlas desde su propio
      dashboard -- solo eligen a qué canal de Discord llegan y qué tipos quieren activar.
    </div>

    <form action="{{ url_for('save_admin_twitch_embeds') }}" method="POST" class="space-y-6">

      {% for key, label in labels.items() %}
        <section class="bg-card border border-border rounded-xl p-6 space-y-4">
          <h2 class="text-lg font-bold text-white">{{ label }}</h2>

          <div class="grid grid-cols-1 md:grid-cols-[1fr_140px] gap-4">
            <div>
              <label class="block text-xs font-bold uppercase text-muted mb-2">Título del embed</label>
              <input type="text" name="{{ key }}_title" data-var-target
                     value="{{ templates[key].title }}"
                     class="embed-title-input w-full bg-panel border border-border rounded-lg px-4 py-3 text-sm focus:outline-none focus:border-accent"
                     data-preview="{{ key }}">
            </div>
            <div>
              <label class="block text-xs font-bold uppercase text-muted mb-2">Color</label>
              <div class="flex items-center gap-2">
                <input type="color" class="embed-color-picker h-11 w-11 rounded-lg border border-border bg-panel cursor-pointer"
                       value="#{{ templates[key].color }}" data-preview="{{ key }}">
                <input type="text" name="{{ key }}_color" value="{{ templates[key].color }}"
                       class="embed-color-hex w-full bg-panel border border-border rounded-lg px-3 py-3 text-sm font-mono uppercase focus:outline-none focus:border-accent"
                       maxlength="6" data-preview="{{ key }}">
              </div>
            </div>
          </div>

          <div>
            <label class="block text-xs font-bold uppercase text-muted mb-2">Descripción</label>
            <textarea name="{{ key }}_description" data-var-target rows="4"
                      class="embed-desc-input w-full bg-panel border border-border rounded-lg px-4 py-3 text-sm font-mono resize-y focus:outline-none focus:border-accent"
                      data-preview="{{ key }}">{{ templates[key].description }}</textarea>
          </div>

          <div>
            <label class="block text-xs font-bold uppercase text-muted mb-2">Footer (opcional)</label>
            <input type="text" name="{{ key }}_footer" data-var-target
                   value="{{ templates[key].footer }}"
                   class="embed-footer-input w-full bg-panel border border-border rounded-lg px-4 py-3 text-sm focus:outline-none focus:border-accent"
                   data-preview="{{ key }}">
          </div>

          {{ vars_panel("vars-panel-" ~ key, variables[key]) }}

          <div>
            <p class="text-xs font-bold uppercase text-muted mb-2">Vista previa</p>
            <div class="discord-preview" id="preview-{{ key }}" style="--preview-color: #{{ templates[key].color }};">
              <div class="preview-title" data-preview-title>{{ templates[key].title }}</div>
              <div data-preview-desc>{{ templates[key].description }}</div>
              <div class="preview-footer" data-preview-footer>{{ templates[key].footer }}</div>
            </div>
          </div>
        </section>
      {% endfor %}

      <div class="flex justify-end">
        <button type="submit"
                class="bg-accent hover:bg-accent/90 text-white text-sm font-semibold px-6 py-3 rounded-lg">
          Guardar plantillas
        </button>
      </div>
    </form>

  </main>

  <script>
    // Paneles de variables: mostrar/ocultar
    document.querySelectorAll(".vars-toggle-btn").forEach((btn) => {
      const panelEl = document.getElementById(btn.dataset.panel);
      const caret = btn.querySelector(".caret");
      btn.addEventListener("click", () => {
        panelEl.classList.toggle("hidden");
        caret.textContent = panelEl.classList.contains("hidden") ? "▾" : "▴";
      });
    });

    // Insertar variable en el último campo enfocado (con data-var-target)
    let lastFocused = null;
    document.querySelectorAll("[data-var-target]").forEach((el) => {
      el.addEventListener("focus", () => { lastFocused = el; });
    });

    document.querySelectorAll(".var-chip").forEach((chip) => {
      chip.addEventListener("click", () => {
        if (!lastFocused) return;
        const token = chip.dataset.token;
        const start = lastFocused.selectionStart ?? lastFocused.value.length;
        const end = lastFocused.selectionEnd ?? lastFocused.value.length;
        const value = lastFocused.value;
        lastFocused.value = value.slice(0, start) + token + value.slice(end);
        lastFocused.dispatchEvent(new Event("input", { bubbles: true }));
        lastFocused.focus();
        const cursor = start + token.length;
        lastFocused.setSelectionRange(cursor, cursor);
      });
    });

    // Vista previa en vivo por sección (título, descripción, footer, color)
    document.querySelectorAll("[data-preview]").forEach((el) => {
      const key = el.dataset.preview;
      const previewBox = document.getElementById(`preview-${key}`);
      if (!previewBox) return;

      const update = () => {
        if (el.classList.contains("embed-title-input")) {
          previewBox.querySelector("[data-preview-title]").textContent = el.value;
        } else if (el.classList.contains("embed-desc-input")) {
          previewBox.querySelector("[data-preview-desc]").textContent = el.value;
        } else if (el.classList.contains("embed-footer-input")) {
          previewBox.querySelector("[data-preview-footer]").textContent = el.value;
        } else if (el.classList.contains("embed-color-picker")) {
          const hex = el.value.replace("#", "").toUpperCase();
          previewBox.style.setProperty("--preview-color", "#" + hex);
          const hexInput = el.parentElement.querySelector(".embed-color-hex");
          if (hexInput) hexInput.value = hex;
        } else if (el.classList.contains("embed-color-hex")) {
          const hex = el.value.replace("#", "");
          if (/^[0-9a-fA-F]{6}$/.test(hex)) {
            previewBox.style.setProperty("--preview-color", "#" + hex);
            const pickerInput = el.parentElement.querySelector(".embed-color-picker");
            if (pickerInput) pickerInput.value = "#" + hex;
          }
        }
      };

      el.addEventListener("input", update);
    });
  </script>
</body>
</html>
