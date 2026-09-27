#!/bin/sh
# Compte-rendu des traitements batch pour Zabbix (et donc pour OpsControl).
#
# Sans lui, Zabbix et OpsControl ne connaissent que la PLANIFICATION d'un batch,
# jamais son résultat. Il ne change rien au batch : il le lance tel quel, note
# son début, son code de sortie et sa durée, et rend le MÊME code de sortie.
#
#   opscontrol-batch-report NOM commande [arguments...]   lancer un batch (crontab)
#   opscontrol-batch-report --discovery                   JSON de découverte (agent Zabbix)
#   opscontrol-batch-report --get NOM champ               une valeur (agent Zabbix)
#
# Pourquoi un fichier lu par l'agent plutôt que zabbix_sender : depuis
# srv-batch-01 et srv-batch-02, le port 10051 du serveur Zabbix est FERMÉ
# zabbix_sender pourrait alors perdre chaque résultat en silence.
# L'agent, lui, est déjà interrogé par Zabbix sur le port 10050 : aucune
# ouverture de pare-feu n'est nécessaire.
#
# État d'un batch : /var/lib/opscontrol-batch/NOM.state (une ligne clé=valeur) :
#   started   début de l'exécution en cours ou de la dernière (epoch)
#   finished  fin de la dernière exécution TERMINÉE (epoch ; 0 = jamais)
#   rc        code de sortie de la dernière exécution terminée (-1 = jamais)
#   duration  durée de la dernière exécution terminée (secondes)
# « En cours » = started > finished. La valeur précédente reste lisible pendant
# qu'un nouveau passage tourne : un batch en cours n'efface pas son dernier résultat.
#
# Garanties : l'écriture de l'état ne fait jamais échouer ni retarder le batch ;
# rien n'est écrit dans la sortie du batch.

DIR="${OPSCONTROL_BATCH_DIR:-/var/lib/opscontrol-batch}"

valide() {
  case "$1" in *[!A-Za-z0-9_.-]*|""|.*) return 1 ;; esac
  return 0
}

lire() {  # NOM champ -> valeur (vide si absente)
  [ -r "$DIR/$1.state" ] || return 0
  sed -n "s/^$2=\(-\{0,1\}[0-9][0-9]*\)$/\1/p" "$DIR/$1.state" | head -n 1
}

ecrire() {  # NOM started finished rc duration — atomique (fichier temporaire + mv)
  tmp="$DIR/.$1.$$"
  printf 'started=%s\nfinished=%s\nrc=%s\nduration=%s\n' "$2" "$3" "$4" "$5" > "$tmp" 2>/dev/null \
    && chmod 0644 "$tmp" 2>/dev/null && mv -f "$tmp" "$DIR/$1.state" 2>/dev/null
  rm -f "$tmp" 2>/dev/null
  return 0
}

case "${1:-}" in
  --discovery)
    printf '{"data":['
    sep=''
    for f in "$DIR"/*.state; do
      [ -e "$f" ] || continue
      n=$(basename "$f" .state)
      valide "$n" || continue
      printf '%s{"{#BATCH}":"%s"}' "$sep" "$n"
      sep=','
    done
    printf ']}\n'
    exit 0 ;;
  --get)
    valide "${2:-}" || exit 1
    case "${3:-}" in started|finished|rc|duration) ;; *) exit 1 ;; esac
    v=$(lire "$2" "$3")
    printf '%s\n' "${v:-0}"
    exit 0 ;;
esac

NAME="${1:-}"
[ $# -ge 2 ] || { echo "usage: opscontrol-batch-report NOM commande [arguments...]" >&2; exit 64; }
valide "$NAME" || { echo "opscontrol-batch-report: NOM invalide (lettres, chiffres, _ . - ; pas de point initial)" >&2; exit 64; }
shift

START=$(date +%s)
PREV_FIN=$(lire "$NAME" finished); PREV_RC=$(lire "$NAME" rc); PREV_DUR=$(lire "$NAME" duration)
ecrire "$NAME" "$START" "${PREV_FIN:-0}" "${PREV_RC:--1}" "${PREV_DUR:-0}"

"$@"
RC=$?

FIN=$(date +%s)
ecrire "$NAME" "$START" "$FIN" "$RC" "$((FIN - START))"
exit "$RC"
