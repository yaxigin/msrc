package code

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	_ "encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"regexp"
	_ "regexp"
	"strconv"
	"strings"
	"time"

	_ "github.com/axgle/mahonia" //编码转换
	"github.com/olekukonko/tablewriter"
	"github.com/parnurzeal/gorequest"
	_ "github.com/thedevsaddam/gojsonq"
	_ "github.com/widuu/gojson"
	"golang.org/x/text/encoding/simplifiedchinese"
	"gopkg.in/yaml.v2"
)

type Fofa struct {
	Results [][]string `json:"results"`
}
type Config struct {
	Fofa struct {
		Email string `yaml:"email"`
		Key   string `yaml:"key"`
	}
	Chinaz struct {
		Key string `yaml:"key"`
	}
}
type Ab struct {
	Cpes      []string      `json:"cpes"`
	Hostnames []string      `json:"hostnames"`
	IP        string        `json:"ip"`
	Ports     []int         `json:"ports"`
	Tags      []interface{} `json:"tags"`
	Vulns     []interface{} `json:"vulns"`
}

type R struct {
	Host   string
	Port   string
	Title  string
	Server string
}
type Charset string

const (
	UTF8     = Charset("UTF-8")
	GB18030  = Charset("GB18030")
	GB2312   = Charset("GB2312")
	GBK      = Charset("GBK")
	filePath = "./code/config.yml"
)

func ConvertByte2String(byte []byte, charset Charset) string {

	var str string
	switch charset {
	case GB18030:
		decodeBytes, _ := simplifiedchinese.GB18030.NewDecoder().Bytes(byte)
		str = string(decodeBytes)
	case UTF8:
		fallthrough
	default:
		str = string(byte)
	}

	return str
}
func UnescapeUnicode(raw []byte) ([]byte, error) {
	str, err := strconv.Unquote(strings.Replace(strconv.Quote(string(raw)), `\\u`, `\u`, -1))
	if err != nil {
		return nil, err
	}
	return []byte(str), nil
}

type Are struct {
	//StateCode int    `json:"StateCode"`
	Reason string `json:"Reason"`
	Result struct {
		Owner       string `json:"Owner"`
		CompanyName string `json:"CompanyName"`
		CompanyType string `json:"CompanyType"`
		SiteLicense string `json:"SiteLicense"`
		SiteName    string `json:"SiteName"`
		MainPage    string `json:"MainPage"`
		VerifyTime  string `json:"VerifyTime"`
	} `json:"Result"`
}
type AB struct {
	Status int    `json:"status"`
	Info   string `json:"info"`
	Data   struct {
		Count   int `json:"count"`
		Current int `json:"current"`
		List    []struct {
			// Avatar      string `json:"avatar"`
			// CompanyID   string `json:"company_id"`
			CompanyName string `json:"company_name"`
		} `json:"list"`
	} `json:"data"`
}

var (
	Search = flag.String("s", "", "fofa 查询")
	Shodan = flag.String("d", "", "shodan 查询")
	gname  = flag.String("n", "", "根据单个厂家名称从天眼查获取域名")
	file   = flag.String("r", "", "请输入txt文件路径 (根据厂家名称从天眼查获取域名)")
	whois  = flag.String("w", "", "请输入域名（可查询备案信息）")
	butian = flag.String("bn", "", "请出入src厂家名称（可以模糊查询）")
	bupage = flag.String("p", "", "请输入src厂家id页(1-189页)")
)

//解析yml文件
func GetConfig() {
	config := Config{}
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Printf("配置文件读取错误: %v", err)
	}
	if yaml.Unmarshal(content, &config) != nil {
		fmt.Printf("解析config.yaml出错: %v", err)
	}
	//fmt.Printf("key: %v", config.Fofa.Email)
	ha(config.Fofa.Email, config.Fofa.Key)
	Tian(config.Chinaz.Key)
}
func ha(email string, key string) {
	flag.Parse()
	if *Search != "" {
		aa := base64.StdEncoding.EncodeToString([]byte(*Search))
		var email string = email
		var key string = key

		var page string = "1"
		var size string = "1000"
		var fields string = "host,port,title,server"
		var url string = "https://fofa.info/api/v1/search/all?email=" + email + "&key=" + key + "&qbase64=" + aa + "&page=" + page + "&size=" + size + "&fields=" + fields
		request := gorequest.New()
		resp, _, _ := request.Get(url).End()
		resp.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36")
		resp.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
		resp.Header.Add("Accept-Language", "zh-CN,zh;q=0.8")
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Print(err)
		}
		var d Fofa
		err = json.Unmarshal(body, &d)
		if err != nil {
			fmt.Println(err)
		}
		if len(d.Results) > 0 {
			data(d.Results)
		}
	}

	if *Shodan != "" {
		a := fmt.Sprintf("%s", *Shodan)
		address := net.ParseIP(a)
		if address == nil {
			iprecords, _ := net.LookupIP(a)
			for _, ip := range iprecords {
				fmt.Printf("\033[36m域名\033[0m:%s \033[35mIP\033[0m:%s\n", a, ip)
				ab := fmt.Sprint(ip)
				U := "https://internetdb.shodan.io/" + ab
				client := &http.Client{}
				resp, err := http.NewRequest("GET", U, nil)
				if err != nil {
					fmt.Println("Fatal error ", err.Error())
					os.Exit(0)
				}
				resp.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36")
				resp.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
				resp.Header.Add("Accept-Language", "zh-CN,zh;q=0.8")
				resp1, err := client.Do(resp)
				if err != nil {
					fmt.Println(err)
				}
				defer resp1.Body.Close()
				body, err := ioutil.ReadAll(resp1.Body)
				if err != nil {
					fmt.Print(err)
				}
				var d Ab
				err = json.Unmarshal(body, &d)
				if err != nil {
					fmt.Println(err)
				}
				fmt.Printf("\033[36mIP\033[0m:%s\n", d.IP)
				if len(d.Ports) != 0 {
					for _, k := range d.Ports {
						fmt.Printf("\033[36m端口\033[0m:%v\n", k)
					}
				}
				for _, k := range d.Hostnames {
					if k != "" {
						fmt.Printf("\033[36m域名\033[0m:%s\n", k)
					}
				}
				for _, k := range d.Cpes {
					if k != "" {
						start := strings.LastIndex(k, ":") + len(":")
						fmt.Printf("\033[36m服务及中间件\033[0m:%s\n", k[start:])
					}
				}
				for _, k := range d.Vulns {
					if k != nil {
						fmt.Printf("\033[36m漏洞\033[0m:%d\n", k)
					}
				}
				for _, k := range d.Tags {
					if k != nil {
						fmt.Printf("\033[36m标签\033[0m:%s\n", k)
					}
				}
				resp1.Body.Close()
			}
		} else {
			ab := fmt.Sprint(address)
			U := "https://internetdb.shodan.io/" + ab
			client := &http.Client{}
			resp, err := http.NewRequest("GET", U, nil)
			if err != nil {
				fmt.Println("Fatal error ", err.Error())
				os.Exit(0)
			}
			resp.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36")
			resp.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
			resp.Header.Add("Accept-Language", "zh-CN,zh;q=0.8")
			resp1, err := client.Do(resp)
			if err != nil {
				fmt.Println(err)
			}
			defer resp1.Body.Close()
			body, err := ioutil.ReadAll(resp1.Body)
			if err != nil {
				fmt.Print(err)
			}
			var d Ab
			err = json.Unmarshal(body, &d)
			if err != nil {
				fmt.Println(err)
			}
			fmt.Printf("\033[36mIP\033[0m:%s\n", d.IP)
			if len(d.Ports) != 0 {
				for _, k := range d.Ports {
					fmt.Printf("\033[36m端口\033[0m:%v\n", k)
				}
			}
			for _, k := range d.Hostnames {
				if k != "" {
					fmt.Printf("\033[36m域名\033[0m:%s\n", k)
				}
			}
			for _, k := range d.Cpes {
				if k != "" {
					start := strings.LastIndex(k, ":") + len(":")
					fmt.Printf("\033[36m服务及中间件\033[0m:%s\n", k[start:])
				}
			}
			for _, k := range d.Vulns {
				if k != nil {
					fmt.Printf("\033[36m漏洞\033[0m:%d\n", k)
				}
			}
			for _, k := range d.Tags {
				if k != nil {
					fmt.Printf("\033[36m标签\033[0m:%s\n", k)
				}
			}
			resp1.Body.Close()
		}

		os.Exit(0)
	}
}

func Tian(key string) {
	flag.Parse()
	if *gname != "" {
		a := *gname
		U := "https://beian.tianyancha.com/search/" + a
		client := &http.Client{}
		resp, err := http.NewRequest("GET", U, nil)
		if err != nil {
			fmt.Println("Fatal error ", err.Error())
			os.Exit(0)
		}
		resp.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36")
		resp.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
		resp.Header.Add("Accept-Language", "zh-CN,zh;q=0.8")
		//resp.Header.Add("Cookie", "")
		resp1, err := client.Do(resp)
		if err != nil {
			fmt.Println(err)
		}
		defer resp1.Body.Close()
		body, err := ioutil.ReadAll(resp1.Body)
		if err != nil {
			fmt.Print(err)
		}
		html := string(body)
		reg := regexp.MustCompile(`<span class="ranking-ym" rel="nofollow">(.*?)</span>`)
		//qq := regexp.MustCompile(`.*(.ICP[备|证]\d{7,10}号[-\d]{0,3})`)
		bb := reg.FindAllStringSubmatch(html, -1)
		//cc := qq.FindAllStringSubmatch(html, -1)
		if len(bb) == 0 {
			fmt.Println(a, "不存在备案信息\n")
		} else {
			fmt.Println(a, "备案信息如下")
			for _, mm := range bb {
				fmt.Println(mm[1])
			}

		}
		os.Exit(0)
	}

	if strings.HasSuffix(*file, ".txt") {
		file1, _ := os.Open(*file)
		defer file1.Close()
		scanner := bufio.NewScanner(file1)
		for scanner.Scan() {
			client := &http.Client{}
			cc := scanner.Text()
			time.Sleep(time.Duration(10) * time.Second)
			UD := "https://beian.tianyancha.com/search/" + cc
			resp, err := http.NewRequest("GET", UD, nil)
			resp.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36")
			resp.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
			//resp.Header.Add("Cookie", "5")
			resp1, err := client.Do(resp)
			if err != nil {
				fmt.Println(err)
			}
			defer resp1.Body.Close()
			body, err := ioutil.ReadAll(resp1.Body)
			if err != nil {
				fmt.Print(err)
			}
			html := string(body)
			//fmt.Print(html)
			reg := regexp.MustCompile(`<span class="ranking-ym" rel="nofollow">(.+?)</span>`)
			bb := reg.FindAllStringSubmatch(html, -1)
			if len(bb) == 0 {
				fmt.Println(cc, "不存在备案信息\n")
			} else {
				fmt.Println(cc, "存在备案信息\n")
				for _, mm := range bb {
					fmt.Println(mm[1])

				}
				// write.Flush()
			}
		}
		os.Exit(0)
	}
	if *whois != "" {
		s := *whois
		url := "https://apidatav2.chinaz.com/single/icp?key=" + key + "&domain=" + s
		client := &http.Client{}
		resp, err := http.NewRequest("GET", url, nil)
		if err != nil {
			fmt.Println("Fatal error ", err.Error())
			os.Exit(0)
		}
		resp.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36")
		resp.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
		resp.Header.Add("Accept-Language", "zh-CN,zh;q=0.8")
		resp1, err := client.Do(resp)
		if err != nil {
			fmt.Println(err)
		}
		defer resp1.Body.Close()
		body, err := ioutil.ReadAll(resp1.Body)
		if err != nil {
			fmt.Print(err)
		}
		//html := ConvertByte2String(body, GB18030)
		// F := []byte(html)
		htmlb := []byte(body)
		var d Are
		err = json.Unmarshal(htmlb, &d)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Printf("\033[36m状态\033[0m:%v\n", d.Reason)
		fmt.Printf("\033[36m公司名称\033[0m:%v\n", d.Result.CompanyName)
		fmt.Printf("\033[36m类型\033[0m:%v\n", d.Result.CompanyType)
		fmt.Printf("\033[36m备案号\033[0m:%v\n", d.Result.SiteLicense)
		fmt.Printf("\033[36m名称\033[0m:%v\n", d.Result.SiteName)
		fmt.Printf("\033[36m域名\033[0m:%v\n", d.Result.MainPage)
		fmt.Printf("\033[36m时间\033[0m:%v\n", d.Result.VerifyTime)
	}
	if *butian != "" || *bupage != "" {
		na := *butian
		p := *bupage
		data := "name=" + na + "&p=" + p
		url := "https://www.butian.net/Reward/pub"
		resp, err := http.Post(url,
			"application/x-www-form-urlencoded",
			strings.NewReader(data))
		resp.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36")
		resp.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
		resp.Header.Add("Accept-Language", "zh-CN,zh;q=0.8")
		if err != nil {
			fmt.Println(err)
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Print(err)
		}
		v, _ := UnescapeUnicode(body)
		//a:=string(v)
		var d AB
		err = json.Unmarshal(v, &d)
		if err != nil {
			fmt.Println(err)
		}
		//fmt.Println(d.Data.List)
		for _, mm := range d.Data.List {
			fmt.Println(mm.CompanyName)
		}

	}
	os.Exit(0)
}

func data(temp [][]string) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"host", "port", "title", "server"})
	table.SetHeaderColor(tablewriter.Colors{tablewriter.Bold, tablewriter.BgGreenColor},
		tablewriter.Colors{tablewriter.FgHiRedColor, tablewriter.Bold, tablewriter.BgBlackColor},
		tablewriter.Colors{tablewriter.BgRedColor, tablewriter.FgWhiteColor},
		tablewriter.Colors{tablewriter.BgCyanColor, tablewriter.FgWhiteColor})

	table.SetColumnColor(tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiBlackColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiRedColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiBlackColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgBlackColor})
	table.AppendBulk(temp)
	table.Render()
}
