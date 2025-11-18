package main

import (
    "net/http"

    "github.com/gin-gonic/gin"
	"example/anonymousvote/utils"
	"github.com/gin-contrib/cors"
)

type VoteRequest struct {
	Seal 	 string `json:"seal"`
	Journal 	string `json:"journal"`
	JournalAbi string `json:"journal_abi"`
	ImageID     string `json:"image_id"`
	Nullifier string `json:"nullifier"`
	Age       uint32 `json:"age"`
	IsStudent bool `json:"is_student"`
	PollID    uint64 `json:"poll_id"`
	OptionA   uint64 `json:"option_a"`
	OptionB   uint64 `json:"option_b"`
}

// album represents data about a record album.
type album struct {
    ID     string  `json:"id"`
    Title  string  `json:"title"`
    Artist string  `json:"artist"`
    Price  float64 `json:"price"`
}

// albums slice to seed record album data.
var albums = []album{
    {ID: "1", Title: "Blue Train", Artist: "John Coltrane", Price: 56.99},
    {ID: "2", Title: "Jeru", Artist: "Gerry Mulligan", Price: 17.99},
    {ID: "3", Title: "Sarah Vaughan and Clifford Brown", Artist: "Sarah Vaughan", Price: 39.99},
}

func main() {
    router := gin.Default()
	router.Use(cors.Default())

    router.GET("/albums", getAlbums)
    router.GET("/albums/:id", getAlbumByID)
    router.POST("/albums", postAlbums)
	router.POST("/checkvote", checkVote)
	router.Static("/web", "./web")

    router.Run("localhost:8080")
}

// checkVote checks a vote
func checkVote(c *gin.Context) {
	var voteRequest utils.VoteRequest
	if err := c.BindJSON(&voteRequest); err != nil {
		c.IndentedJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := utils.Checkvote(&voteRequest)	
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.IndentedJSON(http.StatusOK, gin.H{"status": "success", "result": result})
}


// getAlbums responds with the list of all albums as JSON.
func getAlbums(c *gin.Context) {
    c.IndentedJSON(http.StatusOK, albums)
}

// postAlbums adds an album from JSON received in the request body.
func postAlbums(c *gin.Context) {
    var newAlbum album

    // Call BindJSON to bind the received JSON to
    // newAlbum.
    if err := c.BindJSON(&newAlbum); err != nil {
        return
    }

    // Add the new album to the slice.
    albums = append(albums, newAlbum)
    c.IndentedJSON(http.StatusCreated, newAlbum)
}

// getAlbumByID locates the album whose ID value matches the id
// parameter sent by the client, then returns that album as a response.
func getAlbumByID(c *gin.Context) {
    id := c.Param("id")

    // Loop through the list of albums, looking for
    // an album whose ID value matches the parameter.
    for _, a := range albums {
        if a.ID == id {
            c.IndentedJSON(http.StatusOK, a)
            return
        }
    }
    c.IndentedJSON(http.StatusNotFound, gin.H{"message": "album not found"})
}
