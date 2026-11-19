package emit

import (
	"github.com/kyomufs/proxprobe/internal/model"
)

// Параметры профиля, который поднимает собственное ядро.
//
// Отличается от SubFile не форматом, а назначением: sub.yaml импортируется в
// чужой клиент, у которого свои порт и контроллер, а этот файл — рабочая
// конфигурация ядра, поэтому порт, контроллер и группа прописаны в нём, а не
// задаются флагами командной строки. Значения совпадают с тем, что ждёт
// шлюз: mixed-port — куда стучаться, external-controller — чем
// переключать, группа — что переключать.
const (
	// MihomoFile — имя файла профиля в каталоге ядра.
	MihomoFile = "config.yaml"
	// MihomoPort — порт mixed-прокси, через который ходят запросы.
	MihomoPort = 7891
	// MihomoController — адрес HTTP-API управления ядром.
	MihomoController = "127.0.0.1:9091"
	// MihomoGroup — имя селектора, который переключается по требованию.
	MihomoGroup = "egress"
)

// mihomoProfile — что ядро помнит между запусками.
//
// Выбранный узел не сохраняется: подписка обновляется целиком, и узел,
// выбранный вчера, сегодня может уже не существовать — ядро восстановит его
// из кеша, и весь путь встанет, хотя группа полна живых. Измерено: после
// ночного обновления группа поднялась с узлом, которого в профиле больше нет,
// и каждый запрос умирал на «connect error: context deadline exceeded».
// Первый член группы (DIRECT) и есть дом, с которого начинается запуск.
type mihomoProfile struct {
	StoreSelected bool `yaml:"store-selected"`
}

// mihomoDoc — профиль для собственного ядра.
//
// Порт и контроллер здесь есть намеренно, в отличие от подписки: этот файл
// никто не импортирует, он читается ядром напрямую, и всё, чего в нём нет,
// ядро возьмёт из умолчаний — то есть поднимется на чужих портах.
type mihomoDoc struct {
	MixedPort          int              `yaml:"mixed-port"`
	BindAddress        string           `yaml:"bind-address"`
	ExternalController string           `yaml:"external-controller"`
	Mode               string           `yaml:"mode"`
	LogLevel           string           `yaml:"log-level"`
	Profile            mihomoProfile    `yaml:"profile"`
	Proxies            []map[string]any `yaml:"proxies"`
	ProxyGroups        []map[string]any `yaml:"proxy-groups"`
	Rules              []string         `yaml:"rules"`
}

// Mihomo собирает рабочую конфигурацию ядра для шлюза.
//
// В группе первым стоит DIRECT: пока хост-маршрут жив, повтор запроса не
// нужен, и именно он отвечает чаще всего. Узлы идут следом в порядке
// задержки — это порядок, в котором их пробует переключение.
//
// Группы url-test здесь нет: узлы уже отобраны проверкой, а самопроизвольное
// переключение по задержке спорило бы с тем, кто переключает по отказу, —
// запрос, повторённый через другую ноду, уехал бы обратно в середине.
func Mihomo(nodes []model.Node) ([]byte, error) {
	proxies, names := buildProxies(nodes, MihomoGroup, directName)

	group := append([]string{directName}, names...)
	doc := mihomoDoc{
		MixedPort:          MihomoPort,
		BindAddress:        "127.0.0.1",
		ExternalController: MihomoController,
		Mode:               "rule",
		LogLevel:           "warning",
		Profile:            mihomoProfile{StoreSelected: false},
		Proxies:            proxies,
		ProxyGroups: []map[string]any{{
			"name":    MihomoGroup,
			"type":    "select",
			"proxies": group,
		}},
		Rules: []string{"MATCH," + MihomoGroup},
	}
	return marshalYAML(doc)
}
