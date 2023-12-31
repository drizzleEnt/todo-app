package todo

type TodoList struct {
	Id         int    `json:"id"`
	Title      string `json:"title"`
	Decription string `json:"description"`
}

type UserList struct {
	Id     int
	Userid int
	Listid int
}

type TodoItem struct {
	Id         int    `json:"id"`
	Title      string `json:"title"`
	Decription string `json:"description"`
	Done       bool   `json:"done"`
}

type ListItem struct {
	Id     int
	ListId int
	ItemId int
}
