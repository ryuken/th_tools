package th_tools

type Response struct {
	Status string
	Body   interface{} `json:",string"`
}

func(r *Response) Success(body interface{}) {
    r.Status = "success"
    r.Body = body
}

func(r *Response) Error(body interface{}) {
    r.Status = "error"
    r.Body = body
}
