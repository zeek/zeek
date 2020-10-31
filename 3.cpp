#include <iostream>
#include <string.h>  
#include <fstream>  
#include <vector>  
using namespace std;


class Info_books
{
public:
    string name_books, prodece_books;
    int price_books;
    void addbooks();
    void get_books();
};

class books : public Info_books
{
public:
vector<books> vecbooks;
    void addbooks()
    {   
        books add;

        int k;
        cout << "Enter how many books do you want add?" << endl;
        cin >> k;
        for (int i = 0; i < k; i++)
        {
            cout << "Enter name books" << endl;
            cin >> add.name_books;

            cout << "Enter producer books" << endl;
            cin >> add.prodece_books;
            
            cout << "Enter price books" << endl;
            cin >> add.price_books;

            vecbooks.push_back(add);
        }
    }

    void get_books()
    {
        ofstream file("books_list", ios::app);
        file << "\tYour books list.";
        for (auto i = vecbooks.begin(); i != vecbooks.end(); i++) 
        {
        file << "\nName is - " <<(*i).name_books <<endl;
        file << "Producer is - " <<(*i).prodece_books <<endl;
        file << "Price is - " <<(*i).price_books<<endl;
        }
    }
};

int main()
{
    books g;
    string login;
    int pass; 
    bool w = true; 
    cout << "Enter login administrator." << endl;
    cin >> login;
    cout << "Enter password administrator." << endl;
    cin >> pass;
    if (login == "admin" && pass == 8888)
    {
        while(w)
        {
            cout << "What do you want" << endl;
            cout << "1.Add books" << endl;
            cout << "2.View list about books" << endl;
            int k;
            cin >> k;
            switch (k)
            {
            case 1:
                g.addbooks();
                break;
            case 2:
                g.get_books();
                break;
            
            default:
                cout << "This is not on the list" << endl;
                break;
            }
                cout << "If you want to do something again press 1 or exit press 0 " << endl;
                cin >> w;
        }
    }
        else
        {
            cout << "You are not administrator.";
        }
    return 0;
}